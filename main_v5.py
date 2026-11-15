"""Windows x64 pointer provenance debugger for authorized test processes.
Install: python -m pip install pymem capstone
Run: python -u main_v5.py | python main_v5.py --self-test
Optional: python -u main_v5.py --record-from HEX_ADDRESS --watch HEX_ADDRESS
"""
import argparse
import ctypes as C
from dataclasses import dataclass, field
import faulthandler
import math
import os
import re
import struct
import sys
import tempfile
import time

MASK = (1 << 64) - 1
AMD64 = 0x8664
MAX_CODE = 0x40000
MAX_DEPTH = 64
MAX_INSNS = 65536
REGS = dict(zip(
    'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 rip'.split(),
    range(120, 249, 8)
))
ALIASES = {}
for group in ('rax eax ax al ah', 'rbx ebx bx bl bh', 'rcx ecx cx cl ch',
              'rdx edx dx dl dh', 'rsi esi si sil', 'rdi edi di dil',
              'rsp esp sp spl', 'rbp ebp bp bpl', 'rip eip ip'):
    names = group.split()
    ALIASES.update({name: names[0] for name in names})
for n in range(8, 16):
    ALIASES.update({f'r{n}{s}': f'r{n}' for s in ('', 'd', 'w', 'b')})
ARGUMENTS = {'rcx', 'rdx', 'r8', 'r9'}
NONVOLATILE = {'rbx', 'rbp', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'}
VOLATILE = {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
IGNORE_OPCODES = {'cmp', 'test', 'nop', 'pause', 'bt', 'endbr64', 'lfence',
                  'mfence', 'sfence', 'int3', 'prefetchnta', 'prefetcht0',
                  'prefetcht1', 'prefetcht2', 'comiss', 'comisd', 'ucomiss', 'ucomisd'}
TRACE_OPCODES = {'mov', 'movabs', 'lea', 'add', 'sub', 'inc', 'dec'}
MEMORY_PATTERN = re.compile(
    r'\[\s*([a-z][a-z0-9]*)\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\s*\]', re.I
)


def log(message):
    print(message, flush=True)


def fmt_offset(value):
    return f'{"+" if value >= 0 else "-"}0x{abs(value):X}'


def parse_memory(text):
    match = MEMORY_PATTERN.search(text)
    if not match:
        return None
    reg, sign, number = match.groups()
    offset = int(number, 0) if number else 0
    return reg.lower(), -offset if sign == '-' else offset


class TraceError(Exception):
    pass


class Budget:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def check(self, stage):
        if time.monotonic() >= self.end:
            raise TraceError(f'Analysis time budget exhausted: {stage}')


@dataclass(frozen=True)
class Module:
    name: str
    base: int
    size: int


def containing(modules, address):
    return next((m for m in modules if m.base <= address < m.base + m.size), None)


def label(modules, address):
    m = containing(modules, address)
    return f'{m.name}+0x{address - m.base:X}' if m else f'0x{address:X}'


def get_modules(pm):
    log('[modules] getting loaded module list...')
    out = []
    for m in pm.list_modules():
        name = m.name
        if isinstance(name, bytes):
            name = name.decode(errors='replace')
        out.append(Module(str(name), int(m.lpBaseOfDll), int(m.SizeOfImage)))
    log(f'[modules] {len(out)} loaded modules')
    return out


def read_exact(pm, address, size):
    if size < 0 or address < 0:
        raise TraceError('Invalid memory read range')
    data = pm.read_bytes(address, size)
    if len(data) != size:
        raise TraceError(f'Short read at 0x{address:X}: {len(data)}/{size}')
    return data


def u64(pm, address):
    return struct.unpack('<Q', read_exact(pm, address, 8))[0]


# No pefile, disk PE parsing or full .pdata enumeration.
class FunctionTable:
    def __init__(self, pm, modules, budget, verbose=True):
        self.pm = pm
        self.modules = modules
        self.budget = budget
        self.verbose = verbose
        self.directories = {}

    def say(self, message):
        if self.verbose:
            log(message)

    def directory(self, module):
        if module.base in self.directories:
            return self.directories[module.base]
        self.budget.check('PE headers')
        self.say(f'[pdata] reading PE headers: {module.name}')
        dos = read_exact(self.pm, module.base, 64)
        if dos[:2] != b'MZ':
            raise TraceError(f'{module.name}: invalid MZ signature')
        e_lfanew = struct.unpack_from('<I', dos, 0x3C)[0]
        if not 64 <= e_lfanew <= min(module.size - 24, 0x100000):
            raise TraceError('Invalid PE header offset')
        nt = read_exact(self.pm, module.base + e_lfanew, 24)
        if nt[:4] != b'PE\0\0':
            raise TraceError('Invalid PE signature')
        machine = struct.unpack_from('<H', nt, 4)[0]
        optional_size = struct.unpack_from('<H', nt, 20)[0]
        if machine != AMD64 or optional_size < 144:
            raise TraceError('Not a supported PE32+ AMD64 image')
        if e_lfanew + 24 + optional_size > module.size:
            raise TraceError('Invalid optional header size')
        opt = read_exact(self.pm, module.base + e_lfanew + 24, 144)
        if struct.unpack_from('<H', opt)[0] != 0x20B:
            raise TraceError('Not PE32+')
        if struct.unpack_from('<I', opt, 108)[0] < 4:
            result = (0, 0)
        else:
            rva, size = struct.unpack_from('<II', opt, 136)
            if not rva or not size:
                result = (0, 0)
            else:
                if rva + size > module.size or size % 12:
                    raise TraceError('Invalid exception directory range/size')
                result = (module.base + rva, size // 12)
        self.directories[module.base] = result
        self.say(f'[pdata] {result[1]:,} entries (binary search, no full scan)')
        return result

    def find(self, address):
        self.budget.check('function lookup')
        self.say(f'[pdata] lookup 0x{address:X}')
        module = containing(self.modules, address)
        if module is None:
            return None
        directory, count = self.directory(module)
        rva = address - module.base
        lo, hi = 0, count
        probes = 0
        while lo < hi:
            self.budget.check('pdata binary search')
            mid = (lo + hi) // 2
            begin, end, unwind = struct.unpack(
                '<III', read_exact(self.pm, directory + mid * 12, 12)
            )
            probes += 1
            if rva < begin:
                hi = mid
            elif rva >= end:
                lo = mid + 1
            else:
                if not begin < end <= module.size:
                    raise TraceError('Invalid RUNTIME_FUNCTION entry')
                result = (module.base + begin, module.base + end)
                self.say(f'[pdata] found 0x{result[0]:X}..0x{result[1]:X} ({probes} probes)')
                return result
        self.say(f'[pdata] no entry ({probes} probes)')
        return None


@dataclass
class State:
    reg: str
    operations: list = field(default_factory=list)
    root: int | None = None
    reason: str = ''
    uncertain: bool = False

    def prepend(self, *ops):
        self.operations[:0] = ops
        compact = []
        for kind, value in self.operations:
            if kind == 'add' and compact and compact[-1][0] == 'add':
                compact[-1] = ('add', compact[-1][1] + value)
            else:
                compact.append((kind, value))
        self.operations = [(k, v) for k, v in compact if k != 'add' or v]

    def expr(self, base):
        for kind, value in self.operations:
            if kind == 'add' and value:
                base += fmt_offset(value)
            elif kind == 'deref':
                base = '[' + base + ']'
        return base

    def resolve(self, pm):
        value = self.root
        for kind, arg in self.operations:
            if kind == 'add':
                value = (value + arg) & MASK
            elif kind == 'deref':
                value = u64(pm, value)
        return value


# Imports are deferred so the pure-Python self-test also runs on Linux.
class Decoder:
    def __init__(self, pm, modules, budget):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_RET
        from capstone.x86_const import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
        self.pm, self.modules, self.budget = pm, modules, budget
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.reg_op, self.imm_op, self.mem_op = X86_OP_REG, X86_OP_IMM, X86_OP_MEM
        self.jump, self.ret = CS_GRP_JUMP, CS_GRP_RET
        self.table = FunctionTable(pm, modules, budget)

    def instruction(self, address):
        for length in range(15, 0, -1):
            self.budget.check('target instruction')
            try:
                data = read_exact(self.pm, address, length)
            except Exception:
                continue
            ins = next(self.md.disasm(data, address, count=1), None)
            if ins is not None:
                return ins
        raise TraceError(f'Cannot decode instruction at 0x{address:X}')

# Immutable expressions describe a value at a particular program point.
# ('load', width, address, observed_address) carries an optional alias key.
def K(value):
    return ('const', value & MASK)


def R(name):
    return ('reg', name)


def U(reason):
    return ('unknown', reason)


def stackaddr(value):
    return ('stack', value & MASK)


def signed(value):
    return value if value < 1 << 63 else value - (1 << 64)


def B(op, a, b):
    if op == 'add':
        if a[0] == 'const' and b[0] != 'const':
            a, b = b, a
        if b == K(0):
            return a
        if b[0] == 'const' and a[0] == 'stack':
            return stackaddr(a[1] + b[1])
        if b[0] == 'const' and a[0] == 'add' and a[2][0] == 'const':
            return B('add', a[1], K(a[2][1] + b[1]))
    if op == 'sub' and b[0] == 'const':
        return B('add', a, K(-b[1]))
    if op == 'mul' and b == K(1):
        return a
    if op in ('shl','shr','sar','or','xor') and b == K(0):
        return a
    if op == 'and' and b == K(MASK):
        return a
    if op in ('mul', 'and') and (a == K(0) or b == K(0)):
        return K(0)
    if op in ('xor', 'sub') and a == b:
        return K(0)
    if a[0] == b[0] == 'const':
        x, y = a[1], b[1]
        fn = {'add': lambda: x+y, 'sub': lambda: x-y, 'mul': lambda: x*y,
              'and': lambda: x&y, 'or': lambda: x|y, 'xor': lambda: x^y,
              'shl': lambda: x << (y&63), 'shr': lambda: x >> (y&63),
              'sar': lambda: signed(x) >> (y&63)}[op]
        return K(fn())
    return (op, a, b)


def L(width, address, observed=None):
    if address[0] == 'stack':
        observed = address[1]
    return ('load', width, address, observed)


def cut(expr, bits):
    return expr if bits == 64 else B('and', expr, K((1 << bits)-1))


def extend(expr, bits):
    return B('sub', B('xor', cut(expr, bits), K(1 << (bits-1))), K(1 << (bits-1)))


def leaves(expr):
    kind = expr[0]
    if kind in ('reg', 'unknown', 'stack', 'const'):
        yield expr
    elif kind == 'load':
        yield from leaves(expr[2])
    else:
        yield from leaves(expr[1])
        yield from leaves(expr[2])


def evaluate(expr, pm, regs=None):
    kind = expr[0]
    if kind in ('const', 'stack'):
        return expr[1]
    if kind == 'reg' and regs is not None:
        return regs[expr[1]]
    if kind in ('reg', 'unknown'):
        raise TraceError(f'Unresolved {kind}: {expr[1]}')
    if kind == 'load':
        return int.from_bytes(read_exact(pm, evaluate(expr[2], pm, regs), expr[1]), 'little')
    return B(kind, K(evaluate(expr[1], pm, regs)), K(evaluate(expr[2], pm, regs)))[1]


def render(expr, modules):
    kind = expr[0]
    if kind == 'const':
        return label(modules, expr[1])
    if kind == 'stack':
        return f'stack(0x{expr[1]:X})'
    if kind == 'reg':
        return expr[1]
    if kind == 'unknown':
        return f'?<{expr[1]}>'
    if kind == 'load':
        inner = render(expr[2], modules)
        return f'[{inner}]' if expr[1] == 8 else f'u{expr[1]*8}[{inner}]'
    a, b = expr[1:]
    if kind == 'add' and b[0] == 'const' and not containing(modules, b[1]):
        return render(a, modules) + fmt_offset(signed(b[1]))
    symbol = {'add': '+', 'sub': '-', 'mul': '*', 'and': '&', 'or': '|', 'xor': '^',
              'shl': '<<', 'shr': '>>', 'sar': '>>s'}[kind]
    return f'({render(a, modules)}{symbol}{render(b, modules)})'


def rewrite(expr, registers_map, stores, limit=4000):
    """Simultaneous backward substitution. A newly introduced RHS is pre-state,
    so it must not be rewritten by the same instruction again."""
    count = 0
    def visit(node):
        nonlocal count
        count += 1
        if count > limit:
            raise TraceError('Symbolic expression size limit')
        kind = node[0]
        if kind == 'reg':
            return registers_map.get(node[1], node)
        if kind in ('const', 'stack', 'unknown'):
            return node
        if kind == 'load':
            width, addr, observed = node[1:]
            address = visit(addr)
            for sw, sa, sk, value in stores:
                if observed is not None and sk is not None:
                    delta = observed - sk
                elif address == sa:
                    delta = 0
                else:
                    continue
                if delta >= sw or delta + width <= 0:
                    continue
                if delta >= 0 and delta + width <= sw:
                    return cut(B('shr', value, K(delta * 8)) if delta else value, width * 8)
                return U('overlapping memory write')
            return L(width, address, observed)
        return B(kind, visit(node[1]), visit(node[2]))
    return visit(expr)


MAX_PATHS = 12
MAX_PATH_LENGTH = 4096
MAX_CFG_NODES = 32768
MAX_PATH_EXPANSIONS = 60000


class ProvenanceAnalyzer(Decoder):
    """Bounded CFG predecessor search and backward symbolic dataflow."""
    def __init__(self, pm, modules, budget):
        super().__init__(pm, modules, budget)
        from capstone import CS_AC_WRITE
        self.write_flag = CS_AC_WRITE

    def name(self, ins, op):
        return ins.reg_name(op.reg)

    def address(self, ins, op, stack=None):
        m = op.mem
        # Keep regex as a syntax cross-check, while using Capstone for SIB and widths.
        if not m.index and not m.segment and m.base and sum(x.type==self.mem_op for x in ins.operands)==1:
            parsed=parse_memory(ins.op_str)
            if parsed is not None and parsed!=(ins.reg_name(m.base),m.disp):
                raise TraceError('Regex/Capstone memory operand mismatch')
        if m.segment and ins.reg_name(m.segment) in ('fs', 'gs'):
            return U('FS/GS segment base')
        expr = K(0)
        for ident, scale in ((m.base, 1), (m.index, m.scale)):
            if not ident:
                continue
            name = ins.reg_name(ident)
            root = ALIASES.get(name, name)
            if root == 'rip':
                part = K(ins.address + ins.size)
                if name == 'eip':
                    part = cut(part, 32)
            elif root not in REGS:
                return U(f'address register {name}')
            else:
                part = (stack or {}).get(root, R(root))
                if name != root:
                    part = cut(part, 32)
            expr = B('add', expr, B('mul', part, K(scale)))
        expr = B('add', expr, K(m.disp))
        if getattr(ins, 'addr_size', 8) == 4:
            expr = cut(expr, 32)
        return expr

    def key(self, address, live):
        if address[0] in ('stack', 'const'):
            return address[1]
        if live is not None:
            try:
                return evaluate(address, self.pm, live)
            except Exception:
                pass
        return None

    def reg_value(self, name, width):
        base = ALIASES.get(name, name)
        if base not in REGS:
            return U(f'register {name}')
        expr = R(base)
        if name in ('ah', 'bh', 'ch', 'dh'):
            expr = B('shr', expr, K(8))
        return cut(expr, width*8)

    def source(self, ins, op, stack, live):
        if op.type == self.reg_op:
            return self.reg_value(self.name(ins, op), op.size)
        if op.type == self.imm_op:
            return K(op.imm)
        if op.type == self.mem_op:
            addr = self.address(ins, op, stack)
            return L(op.size, addr, self.key(addr, live))
        return U('unsupported operand')

    def set_dest(self, ins, op, value, replacements, stores, stack, live):
        width = op.size * 8
        if op.type == self.reg_op:
            name = self.name(ins, op)
            root = ALIASES.get(name, name)
            if root not in REGS:
                return
            value = cut(value, width)
            if width < 32:
                shift = 8 if name in ('ah', 'bh', 'ch', 'dh') else 0
                mask = ((1 << width)-1) << shift
                value = B('or', B('and', R(root), K(~mask)),
                          B('shl', value, K(shift)) if shift else value)
            replacements[root] = value
        elif op.type == self.mem_op:
            addr = self.address(ins, op, stack)
            stores.append((op.size, addr, self.key(addr, live), cut(value, width)))

    def transfer(self, ins, expr, stack=None, live=None, recorded=False, next_regs=None):
        m, ops = ins.mnemonic.lower(), ins.operands
        rep, stores = {}, []
        def src(op):
            return self.source(ins, op, stack, live)
        def put(op, val):
            self.set_dest(ins, op, val, rep, stores, stack, live)
        def rsp_address(delta=0):
            return B('add', (stack or {}).get('rsp', R('rsp')), K(delta))
        handled = False
        if m in IGNORE_OPCODES or ins.group(self.jump):
            # LOOP also changes RCX; don't skip that implicit write.
            if not m.startswith('loop'):
                return expr
        if m in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea') and len(ops) == 2:
            val = self.address(ins, ops[1], None) if m == 'lea' else src(ops[1])
            if m in ('movsx', 'movsxd'):
                val = extend(val, ops[1].size * 8)
            put(ops[0], val)
            handled = True
        elif m in ('add','sub','and','or','xor','shl','sal','shr','sar','imul') and len(ops) in (2,3):
            operation = {'sal':'shl','imul':'mul'}.get(m,m)
            a, b = (ops[0], ops[1]) if len(ops)==2 else (ops[1], ops[2])
            # Shift count masking differs between 32- and 64-bit operands.
            right = src(b)
            if operation in ('shl','shr','sar'):
                right = B('and', right, K(63 if ops[0].size==8 else 31))
            left = src(a)
            if operation == 'sar' and ops[0].size < 8:
                left = extend(left, ops[0].size*8)
            put(ops[0], B(operation, left, right))
            handled = True
        elif m in ('inc','dec','neg','not') and len(ops)==1:
            val = src(ops[0])
            val = B('add',val,K(1 if m=='inc' else -1)) if m in ('inc','dec') else B('sub',K(0),val) if m=='neg' else B('xor',val,K(MASK))
            put(ops[0],val)
            handled = True
        elif m == 'xchg' and len(ops)==2:
            put(ops[0],src(ops[1])); put(ops[1],src(ops[0]))
            handled = True
        elif m.startswith('cmov') and len(ops)==2:
            if recorded and live is not None and next_regs is not None:
                # Select by actual pre-instruction flags instead of comparing equal values.
                flags = live.get('eflags')
                cond = condition(m[4:], flags) if flags is not None else None
                put(ops[0],src(ops[1]) if cond is True else src(ops[0]) if cond is False else U(m))
            else:
                put(ops[0],U(f'{m}: conditional data flow; use recording'))
            handled = True
        elif m == 'push' and len(ops)==1:
            size = 2 if ops[0].size==2 else 8
            addr = rsp_address(-size)
            stores.append((size, addr, self.key(addr,live), src(ops[0])))
            rep['rsp'] = B('add',R('rsp'),K(-size))
            handled = True
        elif m == 'pop' and len(ops)==1:
            size = 2 if ops[0].size==2 else 8
            addr = rsp_address()
            rep['rsp'] = B('add',R('rsp'),K(size))
            value=L(size,addr,self.key(addr,live))
            if ops[0].type == self.mem_op:
                # x86 computes a POP memory destination using post-increment RSP.
                dest=self.address(ins,ops[0],stack)
                if ops[0].mem.base and ALIASES.get(ins.reg_name(ops[0].mem.base),ins.reg_name(ops[0].mem.base))=='rsp':
                    dest=B('add',dest,K(size))
                stores.append((size,dest,self.key(dest,live),value))
            else:
                put(ops[0],value)
            handled = True
        elif m == 'leave':
            addr = (stack or {}).get('rbp',R('rbp'))
            rep.update(rsp=B('add',R('rbp'),K(8)),rbp=L(8,addr,self.key(addr,live)))
            handled = True
        elif m == 'call':
            if recorded:
                addr = rsp_address(-8)
                stores.append((8,addr,self.key(addr,live),K(ins.address+ins.size)))
                rep['rsp'] = B('add',R('rsp'),K(-8))
            else:
                rep.update({r:U(f'call clobber {r} at 0x{ins.address:X}') for r in VOLATILE})
                # The callee can write its home space; do not blindly reuse spills there.
                for off in (0,8,16,24):
                    addr = rsp_address(off)
                    stores.append((8,addr,self.key(addr,live),U('call shadow-space clobber')))
            handled = True
        elif ins.group(self.ret):
            if recorded:
                delta = 8 + (ops[0].imm if ops and ops[0].type==self.imm_op else 0)
                rep['rsp'] = B('add',R('rsp'),K(delta))
                handled = True
        elif m.startswith('loop'):
            rep['rcx'] = B('add',R('rcx'),K(-1))
            handled = True
        if not handled:
            _, written = ins.regs_access()
            for ident in written:
                name = ins.reg_name(ident)
                root = ALIASES.get(name,name)
                if root in REGS and root != 'rip':
                    rep[root] = U(f'{m} writes {name} at 0x{ins.address:X}')
            for op in ops:
                if op.type==self.mem_op and getattr(op,'access',0)&self.write_flag:
                    put(op,U(f'{m} memory write'))
        output = rewrite(expr,rep,stores)
        if output != expr:
            log(f'0x{ins.address:X}: {m} {ins.op_str}  =>  {render(output,self.modules)}')
        return output

    def stack_coordinates(self, instructions, endpoint_rsp):
        """Normalize RSP/RBP and stack-derived registers to entry-RSP offsets."""
        coords = {'rsp': 0}
        snapshots = []
        for ins in instructions:
            self.budget.check('stack coordinate tracking')
            snapshots.append(coords.copy())
            m, ops = ins.mnemonic.lower(), ins.operands
            old = coords.copy()
            _, written = ins.regs_access()
            for r in written:
                name = ins.reg_name(r)
                coords.pop(ALIASES.get(name,name),None)
            if m=='call':
                coords.update({r:v for r,v in old.items() if r in NONVOLATILE or r=='rsp'})
                for r in VOLATILE:
                    coords.pop(r,None)
            elif m in ('push','pop'):
                size = 2 if ops and ops[0].size==2 else 8
                if 'rsp' in old and not (m=='pop' and ops and ops[0].type==self.reg_op and self.name(ins,ops[0])=='rsp'):
                    coords['rsp'] = old['rsp'] + (-size if m=='push' else size)
            elif m=='leave' and 'rbp' in old:
                coords['rsp'] = old['rbp']+8
            elif ops and ops[0].type==self.reg_op and ops[0].size==8:
                dst = self.name(ins,ops[0])
                if m in ('mov','movabs') and len(ops)==2 and ops[1].type==self.reg_op:
                    source = self.name(ins,ops[1])
                    if source in old:
                        coords[dst]=old[source]
                elif m=='lea' and len(ops)==2 and ops[1].type==self.mem_op:
                    mem=ops[1].mem
                    base=ins.reg_name(mem.base) if mem.base else None
                    if base in old and not mem.index and not mem.segment:
                        coords[dst]=old[base]+mem.disp
                elif m in ('add','sub') and len(ops)==2 and ops[1].type==self.imm_op and dst in old:
                    coords[dst]=old[dst]+(ops[1].imm if m=='add' else -ops[1].imm)
                elif m in ('inc','dec') and dst in old:
                    coords[dst]=old[dst]+(1 if m=='inc' else -1)
                elif m=='and' and dst=='rsp' and dst in old and len(ops)==2 and ops[1].type==self.imm_op:
                    mask=ops[1].imm&MASK
                    # Win64 function entry RSP % 16 == 8; larger alignments require actual history.
                    if mask in (MASK^7,MASK^15):
                        align=(MASK^mask)+1
                        coords[dst]=old[dst]-((8+old[dst])%align)
        if endpoint_rsp is None or 'rsp' not in coords:
            return [{} for _ in instructions], None
        entry = endpoint_rsp - coords['rsp']
        return [{r:stackaddr(entry+d) for r,d in snap.items()} for snap in snapshots], entry

    def paths(self, start, endpoint, end):
        """Build a reachable CFG, then enumerate bounded predecessors backward."""
        from collections import defaultdict
        if not start <= endpoint < end or end-start>MAX_CODE:
            raise TraceError('Invalid or oversized CFG range')
        data=read_exact(self.pm,start,end-start)
        pending=[start]; decoded={}; predecessors=defaultdict(list); seen=set()
        truncated=False
        while pending:
            self.budget.check('CFG construction')
            pc=pending.pop()
            if pc in seen or not start<=pc<end:
                continue
            seen.add(pc)
            if len(seen)>MAX_CFG_NODES:
                truncated=True; break
            if pc==endpoint:
                continue
            ins=next(self.md.disasm(data[pc-start:pc-start+15],pc,count=1),None)
            if ins is None:
                continue
            decoded[pc]=ins
            nxt=pc+ins.size
            if ins.group(self.ret) or ins.mnemonic in ('int3','ud2','hlt'):
                successors=[]
            elif ins.group(self.jump) or ins.mnemonic.startswith('loop'):
                direct=bool(ins.operands and ins.operands[0].type==self.imm_op)
                successors=[ins.operands[0].imm] if direct else []
                if ins.mnemonic not in ('jmp','ljmp'):
                    successors.append(nxt)
                if not direct:
                    truncated=True
            else:
                successors=[nxt]
            for dest in set(successors):
                if start<=dest<end:
                    predecessors[dest].append(pc)
                    if dest not in seen:
                        pending.append(dest)
        log(f'[cfg] {len(decoded):,} reachable instructions; reverse path search')
        if truncated:
            log('[?] CFG incomplete (indirect jump or node limit)')
        work=[(endpoint,())]; expansions=0; emitted=0
        while work and emitted<MAX_PATHS and expansions<MAX_PATH_EXPANSIONS:
            self.budget.check('CFG predecessor search')
            pc, reverse=work.pop(); expansions+=1
            if pc==start:
                emitted+=1
                yield [decoded[x] for x in reversed(reverse)]
                continue
            if len(reverse)>=MAX_PATH_LENGTH:
                continue
            for pred in predecessors.get(pc,()):
                if reverse.count(pred)<2:
                    work.append((pred,reverse+(pred,)))
        if work:
            log('[?] CFG path budget reached; other paths may exist')

    def caller_sites(self, return_address):
        bounds=self.table.find(return_address-1)
        if bounds is None:
            raise TraceError('Caller has no .pdata entry; cannot establish function boundary')
        start,end=bounds
        for length in range(2,16):
            address=return_address-length
            if address<start:
                break
            try:
                data=read_exact(self.pm,address,length)
            except Exception:
                continue
            ins=next(self.md.disasm(data,address,count=1),None)
            if ins is not None and ins.size==length and ins.mnemonic=='call':
                yield start,address,end

    def access_info(self, target, regs):
        ins=self.instruction(target)
        memory=[op for op in ins.operands if op.type==self.mem_op]
        if len(memory)!=1 or ins.mnemonic=='lea':
            raise TraceError('Target must have one explicit memory access')
        # A single contiguous operand is required; implicit/string, gather,
        # scatter, bit-string and masked accesses need separate semantics.
        name=ins.mnemonic.lower()
        if (any(word in name for word in ('gather','scatter','maskmov','xsave','xrstor'))
                or name in ('bt','btc','btr','bts','prefetchnta','prefetcht0','prefetcht1','prefetcht2')
                or '{' in ins.op_str or name.startswith(('rep ', 'repe ', 'repne '))):
            raise TraceError('Non-contiguous or conditional memory access is unsupported')
        op=memory[0]
        width=int(op.size)
        if width<=0:
            raise TraceError('Unknown memory operand size')
        expr=self.address(ins,op)
        start=evaluate(expr,self.pm,regs)
        if start+width>MASK+1:
            raise TraceError('Memory access range wraps around')
        return ins,expr,start,width

    def target_expr(self, target, regs, watch=None):
        ins,expr,start,width=self.access_info(target,regs)
        log(f'[target] 0x{target:X}: {ins.mnemonic} {ins.op_str}')
        log(f'Effective address: 0x{start:X}')
        log(f'Access size: {width} bytes')
        log(f'Access range: 0x{start:X}..0x{start+width-1:X}')
        if watch is None:
            return expr,start
        delta=watch_delta(start,width,watch)
        if delta is None:
            raise TraceError('Watch address is outside the access range')
        log(f'Watch address: 0x{watch:X}')
        log(f'Access offset: +0x{delta:X}')
        return B('add',expr,K(delta)),watch

    def inspect_candidate(self, expr, expected):
        parts=list(leaves(expr))
        if any(x[0] in ('reg','unknown','stack') for x in parts):
            return False
        if not any(x[0]=='const' and containing(self.modules,x[1]) for x in parts):
            return False
        try:
            value=evaluate(expr,self.pm)
        except Exception as error:
            log(f'[candidate] validation read failed: {error}')
            return False
        log(f'[candidate] {render(expr,self.modules)} -> 0x{value:X}')
        return value==expected

    def report(self, expr, expected, matched, mode):
        log('\n========== POINTER CHAIN ==========')
        log(('Chain: ' if matched else 'Partial chain: ')+render(expr,self.modules))
        log(f'Expected: 0x{expected:X}')
        if matched:
            log('[+] Address matched (module-relative candidate)')
        else:
            log('[!] No validated module-relative root found')
        log(f'[?] {mode}; snapshot match is not proof of future stability')

    def trace(self, frames, regs, target, manual_start, watch=None):
        expr,expected=self.target_expr(target,regs,watch)
        candidates=[expr]; best=expr
        for i,frame in enumerate(frames):
            self.budget.check('frame traversal')
            log(f'\n========== FRAME #{i:02d} ==========')
            log(f'Tracking: {render(candidates[0],self.modules)}')
            if i==0:
                bounds=self.table.find(target)
                if bounds is None and manual_start is None:
                    raise TraceError('No .pdata entry; enter verified function start')
                start=manual_start if manual_start is not None else bounds[0]
                end=bounds[1] if bounds else target+1
                sites=[(start,target,end)]
            else:
                sites=list(self.caller_sites(frame['rip']))
            following=[]; attempted=0
            for start,endpoint,end in sites:
                log(f'[frame] {label(self.modules,start)} -> {label(self.modules,endpoint)}')
                for path in self.paths(start,endpoint,end):
                    attempted+=1
                    snapshots,entry=self.stack_coordinates(path,frame.get('rsp'))
                    log(f'[path #{attempted}] {len(path)} instructions; entry RSP={entry!r}')
                    for candidate in candidates:
                        current=candidate
                        try:
                            for ins,stack in zip(reversed(path),reversed(snapshots)):
                                self.budget.check('backward symbolic trace')
                                current=self.transfer(ins,current,stack)
                            if entry is not None:
                                current=rewrite(current,{'rsp':stackaddr(entry)},[])
                        except (TraceError,RecursionError) as error:
                            log(f'[!] Candidate stopped: {error}')
                            continue
                        best=current
                        if self.inspect_candidate(current,expected):
                            self.report(current,expected,True,'Static CFG path candidate, not execution history')
                            return
                        # Registers surviving into the callee entry can be traced at its caller.
                        # Stack addresses are absolute within this stopped snapshot.
                        current=rewrite(current,{r:U(f'{r} at function entry') for r in VOLATILE-ARGUMENTS},[])
                        if any(x[0]=='unknown' for x in leaves(current)):
                            continue
                        if any(x[0] in ('reg','stack') for x in leaves(current)) and current not in following:
                            following.append(current)
                        if len(following)>=MAX_PATHS:
                            break
                    if len(following)>=MAX_PATHS:
                        break
                if len(following)>=MAX_PATHS:
                    break
            if not following:
                break
            candidates=following
            log(f'[+] Function entry reached; moving to caller with {len(candidates)} candidate(s)')
        self.report(best,expected,False,'Bounded static CFG analysis')

    def trace_recorded(self, history, regs, target, watch=None):
        expr,expected=self.target_expr(target,regs,watch)
        log(f'[record] reversing {len(history):,} executed instructions')
        for index in range(len(history)-1,-1,-1):
            self.budget.check('recorded backward trace')
            ins,before=history[index]
            after=history[index+1][1] if index+1<len(history) else regs
            stack={'rsp':stackaddr(before['rsp'])}
            if abs(before['rbp']-before['rsp'])<0x800000:
                stack['rbp']=stackaddr(before['rbp'])
            expr=self.transfer(ins,expr,stack,before,True,after)
        matched=self.inspect_candidate(expr,expected)
        self.report(expr,expected,matched,'Recorded single-thread path from selected start; other-thread writes not recorded')


def watch_delta(start, width, watch):
    if not (0 <= start <= MASK and width > 0 and start+width <= MASK+1):
        raise TraceError('Invalid memory access range')
    return watch-start if start <= watch < start+width else None


def condition(code, flags):
    c,p,z,s,o=(bool(flags&(1<<bit)) for bit in (0,2,6,7,11))
    return {'o':o,'no':not o,'b':c,'c':c,'nae':c,'ae':not c,'nb':not c,'nc':not c,
            'e':z,'z':z,'ne':not z,'nz':not z,'be':c or z,'na':c or z,
            'a':not(c or z),'nbe':not(c or z),'s':s,'ns':not s,'p':p,'pe':p,'np':not p,'po':not p,
            'l':s!=o,'nge':s!=o,'ge':s==o,'nl':s==o,'le':z or s!=o,'ng':z or s!=o,
            'g':not z and s==o,'nle':not z and s==o}.get(code)


# Windows API structures; explicit fixed widths keep layout auditable.
DWORD, BOOL, HANDLE, PTR = C.c_uint32, C.c_int32, C.c_void_p, C.c_void_p
QWORD = C.c_uint64
EXCEPTION_EVENT, CREATE_PROCESS_EVENT, EXIT_PROCESS_EVENT, LOAD_DLL_EVENT = 1, 3, 5, 6
BREAKPOINT = 0x80000003
CONTINUE, NOT_HANDLED = 0x00010002, 0x80010001


class Address64(C.Structure):
    _fields_ = [('Offset', QWORD), ('Segment', C.c_uint16), ('Mode', C.c_int32)]


class KDHelp64(C.Structure):
    _fields_ = [('Thread', QWORD), ('ThCallbackStack', DWORD), ('ThCallbackBStore', DWORD),
                ('NextCallback', DWORD), ('FramePointer', DWORD), ('KiCallUserMode', QWORD),
                ('KeUserCallbackDispatcher', QWORD), ('SystemRangeStart', QWORD),
                ('KiUserExceptionDispatcher', QWORD), ('StackBase', QWORD), ('StackLimit', QWORD),
                ('BuildVersion', DWORD), ('RetpolineStubFunctionTableSize', DWORD),
                ('RetpolineStubFunctionTable', QWORD), ('RetpolineStubOffset', DWORD),
                ('RetpolineStubSize', DWORD), ('Reserved0', QWORD * 2)]


class StackFrame64(C.Structure):
    _fields_ = [(name, Address64) for name in ('AddrPC', 'AddrReturn', 'AddrFrame', 'AddrStack', 'AddrBStore')] + [
        ('FuncTableEntry', PTR), ('Params', QWORD * 4), ('Far', BOOL), ('Virtual', BOOL),
        ('Reserved', QWORD * 3), ('KdHelp', KDHelp64)]


class ExceptionRecord(C.Structure):
    _fields_ = [('code', DWORD), ('flags', DWORD), ('record', PTR), ('address', PTR),
                ('count', DWORD), ('information', QWORD * 15)]


class ExceptionInfo(C.Structure):
    _fields_ = [('record', ExceptionRecord), ('first_chance', DWORD)]


class EventUnion(C.Union):
    _fields_ = [('exception', ExceptionInfo), ('file', HANDLE), ('raw', C.c_ubyte * 160)]


class DebugEvent(C.Structure):
    _fields_ = [('code', DWORD), ('pid', DWORD), ('tid', DWORD), ('info', EventUnion)]


def check(result, operation):
    if not result:
        error = C.get_last_error()
        raise OSError(error, f'{operation}: {C.FormatError(error)}')
    return result


def context_buffer():
    raw = C.create_string_buffer(1232 + 15)
    return raw, (C.addressof(raw) + 15) & ~15


def registers(context):
    return {name: QWORD.from_address(context + offset).value for name, offset in REGS.items()}


class WinAPI:
    def __init__(self):
        k = C.WinDLL('kernel32', use_last_error=True)
        d = C.WinDLL('dbghelp', use_last_error=True)
        def bind(dll, name, restype, *args):
            fn = getattr(dll, name)
            fn.restype, fn.argtypes = restype, list(args)
            setattr(self, name, fn)
        for name, result, args in [
            ('DebugActiveProcess', BOOL, (DWORD,)), ('DebugActiveProcessStop', BOOL, (DWORD,)),
            ('DebugSetProcessKillOnExit', BOOL, (BOOL,)), ('GetProcessId', DWORD, (HANDLE,)),
            ('CheckRemoteDebuggerPresent', BOOL, (HANDLE, C.POINTER(BOOL))),
            ('WaitForDebugEvent', BOOL, (C.POINTER(DebugEvent), DWORD)),
            ('ContinueDebugEvent', BOOL, (DWORD, DWORD, DWORD)),
            ('OpenThread', HANDLE, (DWORD, BOOL, DWORD)), ('CloseHandle', BOOL, (HANDLE,)),
            ('SuspendThread', DWORD, (HANDLE,)), ('ResumeThread', DWORD, (HANDLE,)),
            ('GetThreadContext', BOOL, (HANDLE, PTR)), ('SetThreadContext', BOOL, (HANDLE, PTR)),
            ('FlushInstructionCache', BOOL, (HANDLE, PTR, C.c_size_t)),
            ('DebugBreakProcess', BOOL, (HANDLE,)), ('IsWow64Process2', BOOL, (HANDLE, C.POINTER(C.c_uint16), C.POINTER(C.c_uint16)))
        ]:
            bind(k, name, result, *args)
        for name, result, args in [
            ('SymInitializeW', BOOL, (HANDLE, C.c_wchar_p, BOOL)), ('SymCleanup', BOOL, (HANDLE,)),
            ('SymSetOptions', DWORD, (DWORD,)), ('SymFunctionTableAccess64', PTR, (HANDLE, QWORD)),
            ('SymGetModuleBase64', QWORD, (HANDLE, QWORD)),
            ('StackWalk64', BOOL, (DWORD, HANDLE, HANDLE, C.POINTER(StackFrame64), PTR, PTR, PTR, PTR, PTR))
        ]:
            bind(d, name, result, *args)

    def get_context(self, thread):
        raw, address = context_buffer()
        C.c_uint32.from_address(address + 48).value = 0x10000B
        check(self.GetThreadContext(thread, address), 'GetThreadContext')
        return raw, address

    def stack(self, pm, thread, context, budget):
        raw, copy = context_buffer()
        C.memmove(copy, context, 1232)
        regs = registers(copy)
        frames = [{'rip': regs['rip'], 'rsp': regs['rsp'], 'rbp': regs['rbp']}]
        sf = StackFrame64()
        # AddrModeFlat == 3. AMD64 frame pointer is optional; use RSP initially.
        for addr, value in ((sf.AddrPC, regs['rip']), (sf.AddrStack, regs['rsp']), (sf.AddrFrame, regs['rsp'])):
            addr.Offset, addr.Mode = value, 3
        seen = {(regs['rip'], regs['rsp'])}
        handle = pm.process_handle
        log('[stack] initializing DbgHelp with local-only symbol path...')
        # DEFERRED_LOADS | FAIL_CRITICAL_ERRORS | IGNORE_NT_SYMPATH | NO_PROMPTS
        self.SymSetOptions(0x4 | 0x200 | 0x1000 | 0x80000)
        with tempfile.TemporaryDirectory(prefix='pointer_symbols_') as path:
            check(self.SymInitializeW(handle, path, True), 'SymInitializeW')
            try:
                for i in range(MAX_DEPTH):
                    budget.check('StackWalk64')
                    log(f'[stack] StackWalk64 step {i + 1}')
                    ok = self.StackWalk64(AMD64, handle, thread, C.byref(sf), copy, None,
                                          C.cast(self.SymFunctionTableAccess64, PTR),
                                          C.cast(self.SymGetModuleBase64, PTR), None)
                    if not ok:
                        log('[stack] StackWalk64 returned FALSE (end or unwind failure)')
                        break
                    rip, rsp = sf.AddrPC.Offset, sf.AddrStack.Offset
                    if not rip:
                        break
                    key = (rip, rsp)
                    if key in seen:
                        if i == 0:
                            continue
                        log('[stack] duplicate frame; stopping')
                        break
                    if rsp < frames[-1]['rsp']:
                        log('[stack] decreasing stack pointer; stopping')
                        break
                    seen.add(key)
                    frames.append({'rip': rip, 'rsp': rsp, 'rbp': sf.AddrFrame.Offset})
            except TraceError as error:
                log(f'[stack] {error}')
            finally:
                log('[stack] SymCleanup')
                self.SymCleanup(handle)
        return frames

    def write_code(self, pm, address, data):
        pm.write_bytes(address, data, len(data))
        check(self.FlushInstructionCache(pm.process_handle, address, len(data)), 'FlushInstructionCache')

    def attach(self, pm):
        handle = pm.process_handle
        pid = check(self.GetProcessId(handle), 'GetProcessId')
        process_machine, native_machine = C.c_uint16(), C.c_uint16()
        check(self.IsWow64Process2(handle, C.byref(process_machine), C.byref(native_machine)), 'IsWow64Process2')
        actual = process_machine.value or native_machine.value
        if actual != AMD64:
            raise TraceError(f'Expected AMD64 target, machine=0x{actual:X}')
        present = BOOL()
        check(self.CheckRemoteDebuggerPresent(handle, C.byref(present)), 'CheckRemoteDebuggerPresent')
        log(f'[attach] PID={pid}, existing debugger={bool(present.value)}')
        if present.value:
            raise TraceError('Another user-mode debugger is attached; detach it first')
        check(self.DebugActiveProcess(pid), 'DebugActiveProcess')
        if not self.DebugSetProcessKillOnExit(False):
            error = C.get_last_error()
            self.DebugActiveProcessStop(pid)
            raise OSError(error, 'DebugSetProcessKillOnExit failed')
        return pid


def analyze_hit(api, pm, thread, context, target, manual, seconds, watch=None):
    budget = Budget(seconds)
    # Prints the actual Python stack if an individual native call stalls.
    faulthandler.dump_traceback_later(5, repeat=True)
    try:
        regs = registers(context)
        log('\n========== REGISTERS ==========')
        for name, value in regs.items():
            log(f'{name.upper():3} = 0x{value:016X}')
        modules = get_modules(pm)
        log('\n========== STACK MEMORY ==========')
        for i in range(16):
            budget.check('stack memory')
            try:
                value = u64(pm, regs['rsp'] + 8 * i)
            except Exception:
                continue
            log(f'RSP+0x{i * 8:02X} | 0x{value:016X} | {label(modules, value)}')
        try:
            frames = api.stack(pm, thread, context, budget)
        except Exception as error:
            log(f'[!] StackWalk64: {error}')
            frames = [{'rip': target, 'rsp': regs['rsp'], 'rbp': regs['rbp']}]
        log('\n========== CALL STACK ==========')
        for i, frame in enumerate(frames):
            log(f'#{i:02d} {label(modules, frame["rip"])} RSP=0x{frame["rsp"]:X}')
        ProvenanceAnalyzer(pm, modules, budget).trace(frames, regs, target, manual, watch)
    finally:
        faulthandler.cancel_dump_traceback_later()


def wait_breakpoint(api, pm, target, manual, seconds, watch=None):
    original = read_exact(pm, target, 1)
    if original == b'\xcc':
        raise TraceError('Target already contains INT3')
    pid = api.attach(pm)
    patched = initialized = exited = cancelling = False
    live_threads = set()
    suspended = {}
    stepping = None
    old_tf = False
    misses = 0
    step_code = 0x80000004
    decoder = None

    def open_thread(tid, rights=0x0008 | 0x0010 | 0x0040):
        return check(api.OpenThread(rights, False, tid), 'OpenThread')

    def suspend_other(tid):
        if tid == stepping or tid in suspended:
            return
        h = open_thread(tid, 0x0002)
        if api.SuspendThread(h) == 0xffffffff:
            error=C.get_last_error()
            api.CloseHandle(h)
            raise OSError(error,'SuspendThread failed')
        suspended[tid]=h

    def resume_others():
        for tid,h in list(suspended.items()):
            if api.ResumeThread(h)==0xffffffff:
                log(f'[!] ResumeThread failed for TID={tid}: {C.get_last_error()}')
            api.CloseHandle(h)
            suspended.pop(tid,None)

    def clear_step():
        nonlocal stepping
        if stepping is None:
            return
        h=open_thread(stepping)
        try:
            raw,ctx=api.get_context(h)
            flag=C.c_uint32.from_address(ctx+68)
            flag.value=(flag.value & ~0x100) | (0x100 if old_tf else 0)
            check(api.SetThreadContext(h,ctx),'restore trap flag')
            stepping=None
        finally:
            api.CloseHandle(h)

    try:
        log('[+] Attached; waiting for initial breakpoint')
        while True:
            event = DebugEvent()
            C.set_last_error(0)
            try:
                ok = api.WaitForDebugEvent(C.byref(event), 250)
            except KeyboardInterrupt:
                if cancelling:
                    raise
                cancelling = True
                log('[!] Cancel requested; pausing target before cleanup')
                check(api.DebugBreakProcess(pm.process_handle), 'DebugBreakProcess')
                continue
            if not ok:
                error = C.get_last_error()
                if error in (121,258):
                    continue
                raise OSError(error,f'WaitForDebugEvent: {C.FormatError(error)}')
            status,finished=CONTINUE,False
            try:
                if event.code in (2,CREATE_PROCESS_EVENT):
                    live_threads.add(event.tid)
                    if event.code==CREATE_PROCESS_EVENT:
                        h=event.info.file
                        if h and h!=PTR(-1).value:
                            api.CloseHandle(h)
                    if stepping is not None and not cancelling:
                        suspend_other(event.tid)
                elif event.code==LOAD_DLL_EVENT:
                    h=event.info.file
                    if h and h!=PTR(-1).value:
                        api.CloseHandle(h)
                elif event.code==4:
                    live_threads.discard(event.tid)
                    h=suspended.pop(event.tid,None)
                    if h:
                        api.CloseHandle(h)
                    if stepping==event.tid:
                        stepping=None
                        resume_others()
                        if cancelling:
                            finished=True
                        else:
                            patched=True
                            api.write_code(pm,target,b'\xcc')
                elif event.code==EXIT_PROCESS_EVENT:
                    exited,patched,finished=True,False,True
                    stepping=None
                    for h in suspended.values():
                        api.CloseHandle(h)
                    suspended.clear()
                    log('[!] Target process exited')
                elif event.code==EXCEPTION_EVENT:
                    record=event.info.exception.record
                    status=NOT_HANDLED
                    if record.code==BREAKPOINT and record.address==target and patched:
                        thread=open_thread(event.tid)
                        try:
                            raw,context=api.get_context(thread)
                            # Restore code and RIP before inspecting or skipping.
                            api.write_code(pm,target,original)
                            patched=False
                            QWORD.from_address(context+REGS['rip']).value=target
                            check(api.SetThreadContext(thread,context),'restore RIP')
                            status=CONTINUE
                            if cancelling:
                                finished=True
                            else:
                                regs=registers(context)
                                delta=0
                                if watch is not None:
                                    if decoder is None:
                                        decoder=ProvenanceAnalyzer(pm,[],Budget(seconds))
                                    decoder.budget=Budget(seconds)
                                    _,_,start,width=decoder.access_info(target,regs)
                                    delta=watch_delta(start,width,watch)
                                if delta is not None:
                                    finished=True
                                    log(f'[+] Breakpoint hit, TID={event.tid}; skipped {misses} nonmatching hits')
                                    try:
                                        analyze_hit(api,pm,thread,context,target,manual,seconds,watch)
                                    except (Exception,KeyboardInterrupt) as error:
                                        log(f'[!] Analysis stopped: {type(error).__name__}: {error}')
                                else:
                                    misses+=1
                                    if misses<=5 or misses%100==0:
                                        log(f'[filter] skip #{misses}: 0x{start:X}..0x{start+width-1:X}; watch=0x{watch:X}')
                                    flag=C.c_uint32.from_address(context+68)
                                    old_tf=bool(flag.value&0x100)
                                    if old_tf:
                                        raise TraceError('Thread already has trap flag set; cannot safely rearm')
                                    stepping=event.tid
                                    # Debug event already suspends all threads. Extra
                                    # suspend counts keep peers paused across single-step.
                                    for tid in live_threads:
                                        suspend_other(tid)
                                    flag.value|=0x100
                                    check(api.SetThreadContext(thread,context),'enable rearm single step')
                        finally:
                            api.CloseHandle(thread)
                    elif record.code==BREAKPOINT and not initialized:
                        initialized,status=True,CONTINUE
                        if cancelling:
                            finished=True
                        else:
                            patched=True
                            api.write_code(pm,target,b'\xcc')
                            log(f'[+] Breakpoint installed: 0x{target:X}; waiting for hit')
                    elif stepping==event.tid and record.code==step_code:
                        status=CONTINUE
                        clear_step()
                        if not cancelling:
                            patched=True
                            api.write_code(pm,target,b'\xcc')
                        else:
                            finished=True
                        resume_others()
                    elif stepping==event.tid:
                        # Do not swallow exceptions generated by the original instruction.
                        clear_step()
                        resume_others()
                        finished=True
                        log('[!] Original instruction raised an exception; stopping filter')
                    elif record.code==BREAKPOINT and cancelling:
                        if patched:
                            api.write_code(pm,target,original)
                            patched=False
                        clear_step()
                        resume_others()
                        status,finished=CONTINUE,True
            except (Exception,KeyboardInterrupt) as error:
                log(f'[!] Debug event stopped: {type(error).__name__}: {error}')
                if patched and not exited:
                    api.write_code(pm,target,original)
                    patched=False
                try:
                    clear_step()
                finally:
                    resume_others()
                finished=True
            finally:
                check(api.ContinueDebugEvent(event.pid,event.tid,status),'ContinueDebugEvent')
            if finished:
                break
    finally:
        try:
            if patched and not exited:
                log('[!] Emergency opcode restore (target may be running)')
                api.write_code(pm,target,original)
            if stepping is not None and not exited:
                log('[!] Abnormal exit during single-step; trap-flag cleanup not guaranteed')
        finally:
            resume_others()
            if not exited:
                if api.DebugActiveProcessStop(pid):
                    log('[+] Debugger detached')
                else:
                    log(f'[!] Debugger detach failed: {C.get_last_error()}')


def wait_recorded(api, pm, start, target, manual, seconds, max_steps, record_seconds, watch=None):
    """Opt-in single-thread recording, starting BEFORE the desired instruction.
    Every history entry is the instruction and register state before execution.
    The ordinary debugger is used when --record-from is not supplied.
    """
    if start == target:
        return wait_breakpoint(api, pm, target, manual, seconds, watch)
    original=read_exact(pm,start,1)
    if original==b'\xcc':
        raise TraceError('Recording start already contains INT3')
    pid=api.attach(pm)
    patched=initialized=exited=cancel=False
    tracked=None; history=[]; analyzer=None; deadline=None; tf_original=False
    step_code=0x80000004
    def flags(context):
        return C.c_uint32.from_address(context+68)
    def thread_handle(tid):
        return check(api.OpenThread(0x0008|0x0010|0x0040,False,tid),'OpenThread')
    def clear_tf():
        nonlocal tracked
        if tracked is None:
            return
        h=thread_handle(tracked)
        try:
            raw,ctx=api.get_context(h)
            flags(ctx).value=(flags(ctx).value&~0x100)|(0x100 if tf_original else 0)
            check(api.SetThreadContext(h,ctx),'restore trap flag')
            tracked=None
        finally:
            api.CloseHandle(h)
    try:
        log('[record] waiting for initial debugger breakpoint')
        while True:
            event=DebugEvent()
            try:
                C.set_last_error(0)
                ok=api.WaitForDebugEvent(C.byref(event),250)
            except KeyboardInterrupt:
                if cancel:
                    raise
                cancel=True; log('[record] cancellation requested')
                check(api.DebugBreakProcess(pm.process_handle),'DebugBreakProcess')
                continue
            if not ok:
                error=C.get_last_error()
                if error not in (121,258):
                    raise OSError(error,f'WaitForDebugEvent: {C.FormatError(error)}')
                if deadline is not None and time.monotonic()>=deadline and not cancel:
                    cancel=True
                    log('[record] time limit; pausing before cleanup')
                    check(api.DebugBreakProcess(pm.process_handle),'DebugBreakProcess')
                continue
            status,finished=CONTINUE,False
            try:
                if event.code in (CREATE_PROCESS_EVENT,LOAD_DLL_EVENT):
                    h=event.info.file
                    if h and h!=PTR(-1).value:
                        api.CloseHandle(h)
                elif event.code==EXIT_PROCESS_EVENT:
                    exited=True; patched=False; tracked=None; finished=True
                elif event.code==4 and event.tid==tracked: # EXIT_THREAD_DEBUG_EVENT
                    tracked=None; finished=True
                    log('[record] traced thread exited')
                elif event.code==EXCEPTION_EVENT:
                    record=event.info.exception.record
                    status=NOT_HANDLED
                    if not initialized and record.code==BREAKPOINT:
                        initialized=True; status=CONTINUE
                        if cancel:
                            finished=True
                        else:
                            api.write_code(pm,start,b'\xcc'); patched=True
                            log(f'[record] start breakpoint: 0x{start:X}')
                    elif patched and record.code==BREAKPOINT and record.address==start:
                        h=thread_handle(event.tid)
                        try:
                            raw,ctx=api.get_context(h)
                            api.write_code(pm,start,original); patched=False
                            QWORD.from_address(ctx+REGS['rip']).value=start
                            check(api.SetThreadContext(h,ctx),'restore recording start RIP')
                            status=CONTINUE
                            if cancel:
                                finished=True
                            else:
                                analyzer=ProvenanceAnalyzer(pm,get_modules(pm),Budget(record_seconds+seconds))
                                before=registers(ctx); before['eflags']=flags(ctx).value
                                tf_original=bool(flags(ctx).value&0x100)
                                if tf_original:
                                    raise TraceError('Target thread already has TF set')
                                history.append((analyzer.instruction(start),before))
                                tracked=event.tid
                                flags(ctx).value|=0x100
                                check(api.SetThreadContext(h,ctx),'enable trap flag')
                                deadline=time.monotonic()+record_seconds
                                log(f'[record] tracing TID={tracked}; max {max_steps} instructions')
                        finally:
                            api.CloseHandle(h)
                    elif tracked==event.tid and record.code==step_code:
                        status=CONTINUE
                        h=thread_handle(tracked)
                        try:
                            raw,ctx=api.get_context(h)
                            before=registers(ctx); before['eflags']=flags(ctx).value
                            pc=before['rip']
                            # A debug trap is after the previous instruction. The target is still unexecuted.
                            hit=pc==target
                            if hit and watch is not None:
                                _,_,access_start,width=analyzer.access_info(target,before)
                                hit=watch_delta(access_start,width,watch) is not None
                                if not hit:
                                    log(f'[filter] recorded hit outside watch: 0x{access_start:X}..0x{access_start+width-1:X}')
                            if hit or cancel or len(history)>=max_steps or time.monotonic()>=deadline:
                                flags(ctx).value=(flags(ctx).value&~0x100)|(0x100 if tf_original else 0)
                                check(api.SetThreadContext(h,ctx),'clear trap flag')
                                tracked=None; finished=True
                                if hit and not cancel:
                                    analyzer.budget=Budget(seconds)
                                    faulthandler.dump_traceback_later(5,repeat=True)
                                    try:
                                        analyzer.trace_recorded(history,before,target,watch)
                                    finally:
                                        faulthandler.cancel_dump_traceback_later()
                                else:
                                    log(f'[record] stopped before target after {len(history)} instructions')
                            else:
                                history.append((analyzer.instruction(pc),before))
                                flags(ctx).value|=0x100
                                check(api.SetThreadContext(h,ctx),'re-enable trap flag')
                                if len(history)%1000==0:
                                    log(f'[record] {len(history):,} instructions; RIP=0x{pc:X}')
                        finally:
                            api.CloseHandle(h)
                    elif tracked==event.tid:
                        # Do not silently follow exception-dispatch transitions.
                        clear_tf(); finished=True
                        log('[record] target exception interrupted history; passing exception to process')
                    elif cancel and record.code==BREAKPOINT:
                        if patched:
                            api.write_code(pm,start,original); patched=False
                        clear_tf(); status=CONTINUE; finished=True
            except (Exception,KeyboardInterrupt) as error:
                log(f'[!] Recording stopped: {type(error).__name__}: {error}')
                if patched:
                    api.write_code(pm,start,original); patched=False
                clear_tf(); finished=True
            finally:
                check(api.ContinueDebugEvent(event.pid,event.tid,status),'ContinueDebugEvent')
            if finished:
                break
    finally:
        try:
            if patched and not exited:
                log('[!] Emergency start opcode restore')
                api.write_code(pm,start,original)
            if tracked is not None and not exited:
                log('[!] Trap flag cleanup could not be guaranteed after abnormal debugger exit')
        finally:
            if not exited:
                if api.DebugActiveProcessStop(pid):
                    log('[+] Debugger detached')
                else:
                    log(f'[!] Debugger detach failed: {C.get_last_error()}')


def self_test():
    # A virtual PE with one million entries; only requested bytes are generated.
    base, pdata, count = 0x140000000, 0x1000, 1_000_000
    class FakeMemory:
        def __init__(self):
            self.entries_read = 0
            self.ptrs = {}
        def read_bytes(self, address, size):
            rva = address - base
            if rva == 0 and size == 64:
                data = bytearray(64); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 0x80)
                return bytes(data)
            if rva == 0x80 and size == 24:
                data = bytearray(24); data[:4] = b'PE\0\0'; struct.pack_into('<H', data, 4, AMD64); struct.pack_into('<H', data, 20, 240)
                return bytes(data)
            if rva == 0x98 and size == 144:
                data = bytearray(144); struct.pack_into('<H', data, 0, 0x20B); struct.pack_into('<I', data, 108, 16); struct.pack_into('<II', data, 136, pdata, count * 12)
                return bytes(data)
            if size == 8 and address in self.ptrs:
                return struct.pack('<Q', self.ptrs[address])
            if size == 12 and pdata <= rva < pdata + count * 12:
                i = (rva - pdata) // 12; begin = 0x1000000 + i * 32
                self.entries_read += 1
                return struct.pack('<III', begin, begin + 24, 0x900)
            raise ValueError(f'unmapped 0x{address:X}')
    pm = FakeMemory()
    modules = [Module('example.exe', base, 0x4000000)]
    table = FunctionTable(pm, modules, Budget(10), False)
    for i in (0, 1, 500000, count - 1):
        begin = base + 0x1000000 + i * 32
        previous = pm.entries_read
        assert table.find(begin + 7) == (begin, begin + 24)
        assert pm.entries_read - previous <= 21
        assert table.find(begin + 28) is None
    assert table.find(base) is None
    assert table.find(base - 1) is None
    log(f'[PASS] PE32+ binary search: {pm.entries_read} entry reads across 9 lookups')
    assert parse_memory('qword ptr [rsi + 0x68]') == ('rsi', 0x68)
    assert parse_memory('[rbx - 0x20]') == ('rbx', -0x20)
    assert parse_memory('[rax + rcx*8]') is None
    state = State('rsi', [('add', 0x68)])
    state.reg = 'rcx'
    state.prepend(('add', 0x30), ('deref', 0))
    state.reg = 'rbx'
    state.root = base + 0x800
    state.prepend(('deref', 0))
    pm.ptrs = {state.root: 0x2000, 0x2030: 0x4000}
    assert state.expr('example.exe+0x800') == '[[example.exe+0x800]+0x30]+0x68'
    assert state.resolve(pm) == 0x4068
    state.prepend(('add', 0), ('add', 16), ('add', -16))
    assert state.resolve(pm) == 0x4068
    assert C.sizeof(DebugEvent) == 176 and DebugEvent.info.offset == 16
    assert ExceptionRecord.address.offset == 16 and C.sizeof(Address64) == 16
    assert StackFrame64.KdHelp.offset == 152 and C.sizeof(KDHelp64) == 112
    log('[PASS] regex, chain composition, pointer resolution, and x64 structure offsets')

    # Test the NEW engine, not the old linear prototype. Fake decoded instructions
    # use Capstone-compatible operand fields; no Windows or Capstone needed.
    from types import SimpleNamespace as NS
    from contextlib import redirect_stdout
    from io import StringIO

    class FakeInsn:
        def __init__(self, address, mnemonic, op_str, ops=(), written=(), size=4, jump=False, ret=False):
            self.address, self.mnemonic, self.op_str = address, mnemonic, op_str
            self.operands, self.written, self.size = ops, written, size
            self.is_jump,self.is_ret=jump,ret
        def regs_access(self):
            return [], self.written
        def reg_name(self, reg):
            return reg
        def group(self, name):
            return (name==10 and self.is_jump) or (name==11 and self.is_ret)

    def reg(name, size=8):
        return NS(type=1, reg=name, size=size)

    def imm(value):
        return NS(type=2, imm=value, size=8)

    def mem(name, offset, index=0, scale=1, size=8, access=1):
        return NS(type=3, size=size, access=access, mem=NS(base=name, disp=offset, index=index, scale=scale, segment=0))

    class MockAnalyzer(ProvenanceAnalyzer):
        def __init__(self):
            self.pm, self.modules, self.budget = pm, modules, Budget(10)
            self.reg_op, self.imm_op, self.mem_op = 1, 2, 3
            self.jump, self.ret, self.write_flag = 10, 11, 2
            self.table = NS(find=lambda addr: next((x for x in ranges if x[0]<=addr<x[1]), None))
            self.md=NS(disasm=lambda data,address,count=1: iter([insns[address]]) if address in insns else iter([]))
        def instruction(self,address):
            return insns[address]

    # Sparse code backing for CFG/read/caller matching tests.
    old_reader=pm.read_bytes
    def test_reader(address,size):
        if any(lo<=address and address+size<=hi for lo,hi in ranges):
            return bytes(size)
        return old_reader(address,size)
    pm.read_bytes=test_reader
    f0,f1,f2=base+0x1000000,base+0x1000100,base+0x1000200
    ranges=[(f,f+64) for f in (f0,f1,f2)]
    root=base+0x800
    pm.ptrs={root:0x2000,0x2030:0x4000}
    # callee: spill RCX using RBP, reload using RSP (same physical stack slot).
    # frame layout: entry rsp=0x8008; push rbp -> 0x8000; sub rsp,0x40 -> 0x7fc0.
    # [rbp-0x10] == [rsp+0x30] == 0x7ff0.
    seq0=[
        FakeInsn(f0,'push','rbp',(reg('rbp'),),('rsp',)),
        FakeInsn(f0+4,'mov','rbp, rsp',(reg('rbp'),reg('rsp')),('rbp',)),
        FakeInsn(f0+8,'sub','rsp, 0x40',(reg('rsp'),imm(0x40)),('rsp',)),
        FakeInsn(f0+12,'mov','[rbp - 0x10], rcx',(mem('rbp',-0x10,access=2),reg('rcx'))),
        FakeInsn(f0+16,'mov','rcx, [rsp + 0x30]',(reg('rcx'),mem('rsp',0x30)),('rcx',)),
        FakeInsn(f0+20,'cmp','rcx, rdi',(reg('rcx'),reg('rdi'))),
    ]
    target=f0+24
    seq1=[FakeInsn(f1,'mov','rcx, [rbx + 0x30]',(reg('rcx'),mem('rbx',0x30)),('rcx',)),
          FakeInsn(f1+4,'call',f'0x{f0:X}',(imm(f0),),('rsp',),5)]
    seq2=[FakeInsn(f2,'mov','rbx, [rip + disp]',(reg('rbx'),mem('rip',root-(f2+7))),('rbx',),7),
          FakeInsn(f2+7,'call',f'0x{f1:X}',(imm(f1),),('rsp',),5)]
    insns={ins.address:ins for ins in seq0+seq1+seq2}
    insns[target]=FakeInsn(target,'mov','eax, [rcx + 0x120]',(reg('eax',4),mem('rcx',0x120,size=4)),('eax',))
    frames=[{'rip':target,'rsp':0x7fc0},{'rip':f1+9,'rsp':0x8010},{'rip':f2+12,'rsp':0x8018}]
    output=StringIO()
    with redirect_stdout(output):
        MockAnalyzer().trace(frames,{'rcx':0x4000},target,None)
    captured=output.getvalue()
    assert 'Chain: [[example.exe+0x800]+0x30]+0x120' in captured,captured
    assert '[+] Address matched' in captured,captured
    assert 'FRAME #02' in captured,captured
    log('[PASS] new CFG engine: RBP spill / RSP reload + three-frame RCX -> RBX chain')
    # SIMD store spans 16 bytes: watch at byte 8 is the exact chain target.
    insns[target]=FakeInsn(target,'movups','[rcx+0x120], xmm0',
                           (mem('rcx',0x120,size=16,access=2),reg('xmm0',16)))
    assert watch_delta(0x4120,16,0x4120)==0
    assert watch_delta(0x4120,16,0x4128)==8
    assert watch_delta(0x4120,16,0x412f)==15
    assert watch_delta(0x4120,16,0x4130) is None
    assert watch_delta(0x4120,16,0x411f) is None
    output=StringIO()
    with redirect_stdout(output):
        MockAnalyzer().trace(frames,{'rcx':0x4000},target,None,0x4128)
    captured=output.getvalue()
    assert 'Chain: [[example.exe+0x800]+0x30]+0x128' in captured,captured
    assert 'Expected: 0x4128' in captured,captured
    assert '[+] Address matched' in captured,captured
    assert 'Access size: 16 bytes' in captured,captured
    try:
        MockAnalyzer().target_expr(target,{'rcx':0x4000},0x4130)
    except TraceError:
        pass
    else:
        raise AssertionError('Out-of-range watch accepted')
    log('[PASS] SIMD store interior watch: exact +8 chain, half-open boundary checks')


    a=MockAnalyzer()
    # Push/pop and stack slots across the frame boundary.
    with redirect_stdout(StringIO()):
        path=[FakeInsn(f0,'push','rcx',(reg('rcx'),),('rsp',)),FakeInsn(f0+4,'pop','rsi',(reg('rsi'),),('rsp','rsi'))]
        coords,entry=a.stack_coordinates(path,0x9008)
        ex=R('rsi')
        for ins,stack in zip(reversed(path),reversed(coords)):
            ex=a.transfer(ins,ex,stack)
        assert ex==R('rcx'),ex
        # Caller writes 5th argument in outbound stack; callee loads it at entry +0x28.
        ex=a.transfer(FakeInsn(f0,'mov','rcx, [rsp+0x28]',(reg('rcx'),mem('rsp',0x28)),('rcx',)),R('rcx'),{'rsp':stackaddr(0x8008)})
        ex=a.transfer(FakeInsn(f1,'mov','[rsp+0x20], rbx',(mem('rsp',0x20,access=2),reg('rbx'))),ex,{'rsp':stackaddr(0x8010)})
        assert ex==R('rbx'),ex
        # 32-bit writes zero-extend; high-byte writes preserve other bits.
        ex=a.transfer(FakeInsn(f0,'mov','ecx, 2',(reg('ecx',4),imm(2)),('ecx',)),R('rcx'))
        assert ex==K(2),ex
        ex=a.transfer(FakeInsn(f0,'mov','ah, 0x12',(reg('ah',1),imm(0x12)),('ah',)),R('rax'))
        assert evaluate(ex,pm,{'rax':0xABCD})==0x12CD,ex
        op=mem('rbx',0x10,'rcx',8)
        fake=FakeInsn(f0,'lea','rax, [rbx+rcx*8+0x10]',(reg('rax'),op),('rax',))
        ex=a.transfer(fake,R('rax'))
        assert evaluate(ex,pm,{'rbx':0x2000,'rcx':3})==0x2028,ex
    log('[PASS] PUSH/POP, cross-frame stack arguments, partial registers, SIB index/scale')

    # CFG: conditional jump chooses either of two root definitions; test both paths.
    root2=base+0x808; pm.ptrs[root2]=0x5000
    b=f0; target=b+20
    insns={b:FakeInsn(b,'jne','0x...', (imm(b+12),), size=4,jump=True),
           b+4:FakeInsn(b+4,'mov','rcx,[rip+root]',(reg('rcx'),mem('rip',root-(b+8))),('rcx',)),
           b+8:FakeInsn(b+8,'jmp','0x...', (imm(target),),size=4,jump=True),
           b+12:FakeInsn(b+12,'mov','rcx,[rip+root2]',(reg('rcx'),mem('rip',root2-(b+16))),('rcx',)),
           b+16:FakeInsn(b+16,'nop',''),
           target:FakeInsn(target,'mov','eax,[rcx+0x120]',(reg('eax',4),mem('rcx',0x120,size=4)),('eax',))}
    output=StringIO()
    with redirect_stdout(output):
        a=MockAnalyzer()
        paths=list(a.paths(b,target,b+64))
        assert len(paths)==2,paths
        a.trace([{'rip':target,'rsp':0x8008}],{'rcx':0x5000},target,None)
    assert 'Chain: [example.exe+0x808]+0x120' in output.getvalue(),output.getvalue()
    log('[PASS] conditional CFG predecessor paths and snapshot validation')

    # Actual-history replay: CALL, a spill, reload, RET and the target in caller.
    # This tests recorded path semantics, not the Windows TF event loop itself.
    pm.ptrs[root]=0x4000
    target=f1+13
    ri=FakeInsn(f1,'mov','rcx,[rip+root]',(reg('rcx'),mem('rip',root-(f1+4))),('rcx',))
    call=FakeInsn(f1+4,'call','callee',(imm(f0),),('rsp',),5)
    push=FakeInsn(f0,'push','rcx',(reg('rcx'),),('rsp',))
    pop=FakeInsn(f0+4,'pop','rax',(reg('rax'),),('rsp','rax'))
    ret=FakeInsn(f0+8,'ret','',(),('rsp',),1,ret=True)
    move=FakeInsn(f1+9,'mov','rcx,rax',(reg('rcx'),reg('rax')),('rcx',))
    insns[target]=FakeInsn(target,'mov','eax,[rcx+0x120]',(reg('eax',4),mem('rcx',0x120,size=4)),('eax',))
    def live(rsp,rcx=0x4000,rax=0):
        return {'rsp':rsp,'rbp':0,'rcx':rcx,'rax':rax,'eflags':0}
    history=[(ri,live(0x8010)),(call,live(0x8010)),(push,live(0x8008)),(pop,live(0x8000)),(ret,live(0x8008,rax=0x4000)),(move,live(0x8010,rax=0x4000))]
    output=StringIO()
    with redirect_stdout(output):
        MockAnalyzer().trace_recorded(history,live(0x8010,rax=0x4000),target)
    assert 'Chain: [example.exe+0x800]+0x120' in output.getvalue(),output.getvalue()
    assert condition('ne',0) is True and condition('ne',0x40) is False
    log('[PASS] recorded instruction replay through CALL/RET + stack spill; condition flags')
    insns[target]=FakeInsn(target,'movups','[rcx+0x120], xmm0',
                           (mem('rcx',0x120,size=16,access=2),reg('xmm0',16)))
    output=StringIO()
    with redirect_stdout(output):
        MockAnalyzer().trace_recorded(history,live(0x8010,rax=0x4000),target,0x4128)
    assert 'Chain: [example.exe+0x800]+0x128' in output.getvalue(),output.getvalue()
    assert 'Expected: 0x4128' in output.getvalue(),output.getvalue()
    log('[PASS] recorded mode: exact SIMD interior watch address')

    try:
        import capstone
    except ImportError:
        log('[SKIP] real Capstone decoding test (package unavailable)')
    else:
        actual=ProvenanceAnalyzer(pm,modules,Budget(10))
        # mov [rsp+0x20],rcx; mov rcx,[rsp+0x20]; lea rax,[rcx+rdx*8+0x10]
        raw=bytes.fromhex('48 89 4c 24 20 48 8b 4c 24 20 48 8d 44 d1 10')
        seq=list(actual.md.disasm(raw,0x1000))
        assert len(seq)==3,[(x.mnemonic,x.op_str) for x in seq]
        coord,_=actual.stack_coordinates(seq,0x8008)
        expr=R('rax')
        with redirect_stdout(StringIO()):
            for ins,stack in zip(reversed(seq),reversed(coord)):
                expr=actual.transfer(ins,expr,stack)
        assert evaluate(expr,pm,{'rcx':0x2000,'rdx':3})==0x2028,expr
        log('[PASS] real Capstone bytes: stack spill/reload + SIB LEA')


def main():
    parser = argparse.ArgumentParser(description='x64 pointer chain candidate tracer')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--timeout', type=float, default=30, help='cooperative analysis budget in seconds (not breakpoint wait)')
    parser.add_argument('--record-from', type=lambda x:int(x,16), help='hex address at which to begin single-step history')
    parser.add_argument('--watch', type=lambda x:int(x,16), help='exact data address (hex); omit to prompt')
    parser.add_argument('--max-steps', type=int, default=20000)
    parser.add_argument('--record-timeout', type=float, default=60)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if os.name != 'nt' or C.sizeof(PTR) != 8:
        raise SystemExit('Windows x64 and 64-bit Python required')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be positive')
    if args.max_steps <= 0 or not math.isfinite(args.record_timeout) or args.record_timeout <= 0:
        parser.error('record limits must be positive')
    import pymem
    api = WinAPI()
    log('========== POINTER CHAIN FINDER ==========')
    name = input('Process name or PID: ').strip()
    target = int(input('Breakpoint address (hex): ').strip(), 16)
    watch=args.watch
    if watch is None:
        watch_text=input('Watch address (hex, Enter = access start): ').strip()
        watch=int(watch_text,16) if watch_text else None
    if watch is not None and not 0<=watch<=MASK:
        raise TraceError('Invalid watch address')
    text = input('Function start (Enter = AUTO): ').strip()
    manual = int(text, 16) if text else None
    if target <= 0 or (manual is not None and not 0 < manual <= target):
        raise TraceError('Invalid address range')
    pm = pymem.Pymem()
    if name.isdecimal():
        pm.open_process_from_id(int(name))
    else:
        pm.open_process_from_name(name, exact_match=True)
    try:
        if args.record_from is None:
            wait_breakpoint(api, pm, target, manual, args.timeout, watch)
        else:
            wait_recorded(api, pm, args.record_from, target, manual, args.timeout, args.max_steps, args.record_timeout, watch)
    finally:
        pm.close_process()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log('[!] Cancelled')
    except (TraceError, OSError, ValueError) as error:
        log(f'[!] {type(error).__name__}: {error}')
        sys.exit(1)
