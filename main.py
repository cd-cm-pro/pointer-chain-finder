"""Windows x64 pointer provenance debugger for authorized test processes.
Install: python -m pip install pymem capstone
Run: python -u main_v6_types_scan.py | python main_v6_types_scan.py --self-test
Value formats: python main_v6_types_scan.py --list-types
"""
import argparse
from bisect import bisect_left
import codecs
from collections import defaultdict
import ctypes as C
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
import math
import os
import re
import struct
import sys
import tempfile
import time
from typing import Callable

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


MAX_VALUE_BYTES = 1 << 20
VALUE_FORMATS = """Value formats for --type (default: auto):
  auto                       raw bytes from the watch address to the end of the access
  all                        raw bytes and common scalar interpretations that fit
  i8/u8 ... i128/u128        signed/unsigned integers; any positive multiple of 8 bits
  f16, bf16, f32, f64        binary16, bfloat16, binary32, binary64
  f80, f128                  x87 80-bit extended and IEEE binary128
  bool, bool32               1-byte bool and 4-byte Windows BOOL
  ptr, ptr32                 64-bit and 32-bit hexadecimal pointer values
  char, wchar                single byte, UTF-16 code unit
  bytes[N]                   raw bytes (aob[N] also works)
  bits[OFFSET:WIDTH]         unsigned bit field (sbits[...] for signed)
  ascii[N], latin1[N]        fixed-size single-byte strings
  utf8[N], utf16[N], utf32[N] fixed-size strings; N counts code units
  cstr[N], cutf16[N], ...    NUL-terminated strings with a maximum of N code units
  text:ENCODING[N]           custom text encoding; ctext:... stops at NUL
  TYPE[N]                    fixed-size array, e.g. f32[3] or u16[3][2]
  struct:FORMAT              Python struct layout, e.g. struct:<ifB3x
  none                       show only the pointer chain
Use --endian big for big-endian values; little-endian is the default.
Aliases include byte, word, dword, qword, short, int, long, float, double, pointer, str[N].
Explicit values are read from the watch address before the instruction runs.
Fixed-size reads support up to 1 MiB.
"""


@dataclass(frozen=True)
class ValueType:
    name: str
    size: int | None
    decode: Callable[[bytes], str]
    nul_unit: int = 0
    match_size: int | None = None
    match_offset: int = 0

    def __post_init__(self):
        if self.size is not None and not 1 <= self.size <= MAX_VALUE_BYTES:
            raise ValueError(f'Type size must be between 1 and {MAX_VALUE_BYTES:,} bytes')

    @property
    def watch_range(self):
        return self.match_size or self.size or 1, self.match_offset


def format_integer(value):
    # Python limits conversion of very large integers to decimal strings.
    return str(value) if value.bit_length() <= 4096 else hex(value)


def format_float(value, digits):
    if math.isnan(value) and math.copysign(1, value) < 0:
        return '-nan'
    if not math.isfinite(value) or value == 0:
        return repr(value)
    return format(value, f'.{digits}g')


def format_extended_float(data, order, fraction_bits, explicit_integer):
    bits = int.from_bytes(data, order)
    width = fraction_bits + int(explicit_integer)
    fraction = bits & ((1 << fraction_bits) - 1)
    significand = bits & ((1 << width) - 1)
    exponent = (bits >> width) & 0x7fff
    sign = '-' if bits >> (width + 15) else ''
    if explicit_integer and exponent and not significand >> fraction_bits:
        return f'unsupported x87 encoding (0x{bits:020X})'
    if exponent == 0x7fff:
        return sign + ('nan' if fraction else 'inf')
    if exponent and not explicit_integer:
        significand |= 1 << fraction_bits
    if not significand:
        return sign + '0.0'
    with localcontext() as context:
        digits = 21 if explicit_integer else 36
        context.prec = digits + 16
        value = Decimal(significand) * Decimal(2) ** (max(1, exponent) - 16383 - fraction_bits)
        return sign + format(value, f'.{digits}g')


TYPE_ALIASES = {
    'byte': 'u8', 'word': 'u16', 'dword': 'u32', 'qword': 'u64',
    '1byte': 'u8', '2bytes': 'u16', '4bytes': 'u32', '8bytes': 'u64',
    'sbyte': 'i8', 'short': 'i16', 'ushort': 'u16', 'int': 'i32', 'uint': 'u32',
    'long': 'i32', 'ulong': 'u32', 'longlong': 'i64', 'ulonglong': 'u64',
    'size_t': 'u64', 'intptr': 'i64', 'uintptr': 'u64', 'pointer': 'ptr', 'ptr64': 'ptr',
    'half': 'f16', 'float': 'f32', 'single': 'f32', 'double': 'f64',
    'bfloat16': 'bf16', 'x87': 'f80', 'quad': 'f128', 'boolean': 'bool',
}
TEXT_TYPES = {
    'char': ('latin-1', 1), 'ascii': ('ascii', 1), 'latin1': ('latin-1', 1),
    'str': ('utf-8', 1), 'utf8': ('utf-8', 1), 'wchar': ('utf-16', 2),
    'utf16': ('utf-16', 2), 'utf32': ('utf-32', 4),
}
BINARY_FLOATS = {
    'f16': ('e', 2, 5), 'f32': ('f', 4, 9), 'f64': ('d', 8, 17), 'bf16': ('f', 2, 9),
}


def normalized_name(text):
    return ''.join(text.lower().split())


def format_bytes(data):
    return data.hex(' ').upper()


def text_type(name, encoding, unit, count, order, terminated):
    if encoding in ('utf-16', 'utf-32'):
        encoding += '-le' if order == 'little' else '-be'

    def decode(data):
        if terminated:
            sentinel = bytes(unit)
            end = next((i for i in range(0, len(data), unit) if data[i:i + unit] == sentinel), len(data))
            data = data[:end]
        return repr(data.decode(encoding, errors='backslashreplace'))

    return ValueType(name, count * unit, decode, unit if terminated else 0)


def parse_value_type(text, order='little'):
    text = text.strip()
    endian = '<' if order == 'little' else '>'
    array = re.fullmatch(r'(.+)\[\s*([0-9]+)\s*\]', text)
    if array is None and text.lower().startswith('struct:'):
        layout = text.split(':', 1)[1].strip()
        if not layout:
            raise ValueError('struct: requires a Python struct format')
        try:
            fmt = struct.Struct(layout if layout[0] in '@=<>!' else endian + layout)
        except struct.error as error:
            raise ValueError(str(error)) from error
        return ValueType('struct:' + fmt.format, fmt.size, lambda data: repr(fmt.unpack(data)))

    name = normalized_name(text)
    name = TYPE_ALIASES.get(name, name)
    if name == 'none':
        return None
    if name == 'auto':
        return ValueType('auto', None, format_bytes)
    if name == 'all':
        scalars = [parse_value_type(item, order) for item in
                   'bool bool32 u8 i8 u16 i16 u32 i32 u64 i64 u128 i128 f16 bf16 f32 f64 f80 f128 ptr32 ptr'.split()]

        def interpretations(data):
            values = [f'{item.name}={item.decode(data[:item.size])}' for item in scalars
                      if item.size <= len(data)]
            return format_bytes(data) + ' | ' + ', '.join(values)

        return ValueType('all', None, interpretations)

    integer = re.fullmatch(r'(i|int|u|uint)([0-9]+)', name)
    if integer:
        kind, width = integer.groups()
        bits = int(width)
        if bits <= 0 or bits % 8:
            raise ValueError('Integer width must be a positive multiple of 8 bits')
        signed_value = kind in ('i', 'int')
        return ValueType(('i' if signed_value else 'u') + str(bits), bits // 8,
                         lambda data: format_integer(int.from_bytes(data, order, signed=signed_value)))

    if re.fullmatch(r'float[0-9]+', name):
        name = 'f' + name[5:]
    if name in BINARY_FLOATS:
        code, size, digits = BINARY_FLOATS[name]

        def decode_float(data):
            if name == 'bf16':
                data = (int.from_bytes(data, order) << 16).to_bytes(4, order)
            return format_float(struct.unpack(endian + code, data)[0], digits)

        return ValueType('float' + name[1:] if name != 'bf16' else name, size, decode_float)
    if name in ('f80', 'f128'):
        explicit = name == 'f80'
        return ValueType('float' + name[1:], 10 if explicit else 16,
                         lambda data: format_extended_float(data, order, 63 if explicit else 112, explicit))
    if name in ('bool', 'bool32'):
        return ValueType(name, 1 if name == 'bool' else 4,
                         lambda data: 'true' if any(data) else 'false')
    if name in ('ptr32', 'ptr'):
        size = 4 if name == 'ptr32' else 8
        return ValueType(name, size, lambda data: f'0x{int.from_bytes(data, order):0{size * 2}X}')
    if name in ('char', 'wchar'):
        encoding, unit = TEXT_TYPES[name]
        return text_type(name, encoding, unit, 1, order, False)

    field = re.fullmatch(r'(s?)bits\[([0-9]+):([0-9]+)\]', name)
    if field:
        sign, start, length = field.groups()
        offset, width = int(start), int(length)
        if width <= 0:
            raise ValueError('Bit-field width must be positive')

        def decode_field(data):
            value = (int.from_bytes(data, order) >> offset) & ((1 << width) - 1)
            if sign and value >> (width - 1):
                value -= 1 << width
            return format_integer(value)

        size = (offset + width + 7) // 8
        skip = offset // 8
        return ValueType(name, size, decode_field, match_size=size - skip,
                         match_offset=skip if order == 'little' else 0)

    if array:
        element, amount = array.groups()
        count = int(amount)
        key = normalized_name(element)
        if key.startswith(('text:', 'ctext:')):
            kind, codec = key.split(':', 1)
            try:
                encoding = codecs.lookup(codec).name
                b''.decode(encoding)
            except LookupError as error:
                raise ValueError(f'Unknown text encoding {codec!r}') from error
            unit = 2 if encoding.startswith('utf-16') else 4 if encoding.startswith('utf-32') else 1
            return text_type(name, encoding, unit, count, order, kind == 'ctext')
        if key in ('bytearray', 'bytes', 'aob', 'raw'):
            return ValueType(f'bytes[{count}]', count, format_bytes)
        terminated = key.startswith('c') and key[1:] in TEXT_TYPES
        codec = key[1:] if terminated else key
        if codec in TEXT_TYPES:
            encoding, unit = TEXT_TYPES[codec]
            return text_type(name, encoding, unit, count, order, terminated)
        item = parse_value_type(element, order)
        if item is None or item.size is None:
            raise ValueError('Array element must have a fixed size')
        return ValueType(f'{item.name}[{count}]', count * item.size,
                         lambda data: '[' + ', '.join(item.decode(data[i:i + item.size])
                                                      for i in range(0, len(data), item.size)) + ']')
    raise ValueError(f'Unknown value type {text!r}. Use --list-types for supported formats.')


def read_value(pm, address, spec, size):
    if not 0 <= address <= MASK or not 0 < size <= MAX_VALUE_BYTES or address + size > MASK + 1:
        raise TraceError('Invalid value read range')
    if not spec.nul_unit:
        return spec.decode(read_exact(pm, address, size))
    # A string ending just before an unreadable page is still readable.
    data = bytearray()
    unit = spec.nul_unit
    sentinel = bytes(unit)
    while len(data) < size:
        cursor = address + len(data)
        block_size = min(256, size - len(data))
        try:
            block = read_exact(pm, cursor, block_size)
        except Exception:
            block = read_exact(pm, cursor, unit)
        for offset in range(0, len(block), unit):
            piece = block[offset:offset + unit]
            if piece == sentinel:
                return spec.decode(bytes(data))
            data.extend(piece)
    return spec.decode(bytes(data))


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


def stack_loads(expr):
    kind = expr[0]
    if kind == 'load':
        address = expr[2]
        if address[0] == 'stack':
            yield address[1]
        yield from stack_loads(address)
    elif kind not in ('const', 'stack', 'reg', 'unknown'):
        yield from stack_loads(expr[1])
        yield from stack_loads(expr[2])


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
MAX_INLINE_DEPTH = 6
MAX_INLINE_ATTEMPTS = 128
LEAF_WINDOW = 0x400


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

    def transfer(self, ins, expr, stack=None, live=None, recorded=False, next_regs=None,
                 conditional=None):
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
            val = self.address(ins, ops[1], stack) if m == 'lea' else src(ops[1])
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
                conditional = condition(m[4:], flags) if flags is not None else None
            put(ops[0], src(ops[1]) if conditional is True else
                src(ops[0]) if conditional is False else U(f'{m}: conditional data flow'))
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
            message=f'0x{ins.address:X}: {m} {ins.op_str}  =>  {render(output,self.modules)}'
            seen=getattr(self,'trace_messages',None)
            if seen is None or (message not in seen and len(seen)<MAX_INSNS):
                log(message)
                if seen is not None:
                    seen.add(message)
        return output

    def stack_coordinates(self, instructions, endpoint_rsp=None, *, entry_rsp=None,
                          entry_coordinates=None):
        """Normalize RSP/RBP and stack-derived registers to entry-RSP offsets."""
        coords = {'rsp': 0}
        if entry_rsp is not None:
            coords.update({name: value[1] - entry_rsp for name, value in
                           (entry_coordinates or {}).items() if name != 'rsp'})
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
        if entry_rsp is None and (endpoint_rsp is None or 'rsp' not in coords):
            return [{} for _ in instructions], None
        entry = entry_rsp if entry_rsp is not None else endpoint_rsp - coords['rsp']
        return [{r:stackaddr(entry+d) for r,d in snap.items()} for snap in snapshots], entry

    def graph(self, start, end, endpoint=None, *, leaf=False):
        if not start < end <= start + MAX_CODE or endpoint is not None and not start <= endpoint < end:
            raise TraceError('Invalid or oversized CFG range')
        data=None if leaf else read_exact(self.pm,start,end-start)
        pending=[start]; decoded={}; predecessors=defaultdict(list); seen=set()
        exits=[]
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
            if leaf:
                try:
                    ins=self.instruction(pc)
                except (TraceError, KeyError):
                    truncated=True
                    continue
            else:
                ins=next(self.md.disasm(data[pc-start:pc-start+15],pc,count=1),None)
            if ins is None:
                truncated=True
                continue
            decoded[pc]=ins
            nxt=pc+ins.size
            if ins.group(self.ret) or ins.mnemonic in ('int3','ud2','hlt'):
                successors=[]
                if ins.mnemonic == 'ret':
                    exits.append(ins)
            elif ins.group(self.jump) or ins.mnemonic.startswith('loop'):
                direct=bool(ins.operands and ins.operands[0].type==self.imm_op)
                successors=[ins.operands[0].imm] if direct else []
                if ins.mnemonic not in ('jmp','ljmp'):
                    successors.append(nxt)
                if ins.mnemonic == 'jmp' and (not direct or not start <= successors[0] < end):
                    exits.append(ins)
                if not direct or any(not start <= dest < end for dest in successors):
                    truncated=True
            else:
                successors=[nxt]
            for dest in dict.fromkeys(successors):
                if start<=dest<end:
                    predecessors[dest].append(pc)
                    if dest not in seen:
                        pending.append(dest)
        return decoded,predecessors,exits,truncated

    def paths(self, start, endpoint, end):
        """Build a reachable CFG, then enumerate bounded predecessors backward."""
        decoded,predecessors,_,truncated=self.graph(start,end,endpoint)
        log(f'[cfg] {len(decoded):,} reachable instructions; reverse path search')
        if truncated:
            log('[?] CFG incomplete (undecodable code, external/indirect branch, or node limit)')
        yield from self.predecessor_paths(start,endpoint,decoded,predecessors)

    def predecessor_paths(self,start,endpoint,decoded,predecessors):
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

    def branch_target(self, ins, prefix, snapshots):
        if not ins.operands:
            return None
        expr=self.source(ins,ins.operands[0],snapshots[-1],None)
        for earlier,stack in zip(reversed(prefix),reversed(snapshots[:-1])):
            if not any(part[0]=='reg' for part in leaves(expr)) and next(stack_loads(expr),None) is None:
                break
            self.budget.check('indirect call target')
            expr=self.transfer(earlier,expr,stack)
        try:
            return evaluate(expr,self.pm)
        except Exception:
            return None

    def return_values(self, destination, expr, entry_rsp, coordinates, active):
        if destination in active or len(active)>=MAX_INLINE_DEPTH or self.inline_attempts>=MAX_INLINE_ATTEMPTS:
            return
        self.inline_attempts+=1
        self.budget.check('callee analysis')
        if destination not in self.callee_graphs:
            bounds=self.table.find(destination)
            if bounds:
                self.callee_graphs[destination]=self.graph(destination,bounds[1])
            else:
                module=containing(self.modules,destination)
                end=min(destination+LEAF_WINDOW,module.base+module.size) if module else destination+LEAF_WINDOW
                self.callee_graphs[destination]=self.graph(destination,end,leaf=True)
        decoded,predecessors,exits,_=self.callee_graphs[destination]
        active=active+(destination,)
        attempts=0
        for terminal in sorted(exits,key=lambda ins: ins.address):
            for path in self.predecessor_paths(destination,terminal.address,decoded,predecessors):
                if attempts>=MAX_PATHS:
                    return
                attempts+=1
                # At a Win64 near RET or tail jump, the callee must have restored its stack.
                snapshots,_=self.stack_coordinates(path+[terminal],entry_rsp=entry_rsp,
                    entry_coordinates=coordinates)
                if entry_rsp is not None and snapshots[-1].get('rsp')!=stackaddr(entry_rsp):
                    continue
                if terminal.mnemonic=='ret':
                    if terminal.operands:
                        continue
                    current=self.transfer(terminal,expr,snapshots[-1],recorded=True)
                else:
                    tail=self.branch_target(terminal,path,snapshots)
                    if not tail:
                        continue
                    for current in self.return_values(tail,expr,entry_rsp,snapshots[-1],active):
                        yield from self.rewind(path,snapshots[:-1],current,active)
                    continue
                yield from self.rewind(path,snapshots[:-1],current,active)

    def call_affects(self, expr, stack):
        if any(part[0]=='reg' and part[1] in VOLATILE for part in leaves(expr)):
            return True
        if 'rsp' not in stack:
            return False
        rsp=stack['rsp'][1]
        out_args={stack[name][1] for name in ARGUMENTS if name in stack}
        return any(address in out_args or (rsp<=address and (address<rsp+32 or out_args))
                   for address in stack_loads(expr))

    def rewind(self,path,snapshots,expr,active=(),live=None):
        candidates=[expr]
        surviving={name:K(value) for name,value in (live or {}).items()
                   if name in REGS and name not in ('rsp','rip')}
        for i in range(len(path)-1,-1,-1):
            self.budget.check('backward symbolic trace')
            ins,stack=path[i],snapshots[i]
            if surviving:
                _,written=ins.regs_access()
                for ident in written:
                    name=ins.reg_name(ident)
                    surviving.pop(ALIASES.get(name,name),None)
                if ins.mnemonic=='call':
                    for name in VOLATILE:
                        surviving.pop(name,None)
            next_candidates=[]
            for current in candidates:
                values=[]
                if ins.mnemonic=='call' and self.call_affects(current,stack):
                    try:
                        destination=self.branch_target(ins,path[:i],snapshots[:i+1])
                        if destination:
                            log(f'[call] 0x{ins.address:X} -> {label(self.modules,destination)}; tracing return paths')
                            entry=stack['rsp'][1]-8 if 'rsp' in stack else None
                            for value in self.return_values(destination,current,entry,stack,active):
                                values.append(self.transfer(ins,value,stack,recorded=True))
                                if len(values)>=MAX_PATHS:
                                    break
                    except Exception as error:
                        log(f'[call] Incomplete callee trace: {error}')
                elif ins.mnemonic.startswith('cmov'):
                    values=[self.transfer(ins,current,stack,conditional=choice) for choice in (False,True)]
                if not values:
                    values=[self.transfer(ins,current,stack)]
                for value in values:
                    if value not in next_candidates:
                        next_candidates.append(value)
                    if len(next_candidates)>=MAX_PATHS:
                        break
                if len(next_candidates)>=MAX_PATHS:
                    break
            candidates=next_candidates
            if surviving:
                for value in candidates:
                    names={part[1] for part in leaves(value) if part[0]=='reg'}
                    if names and names<=surviving.keys() and next(stack_loads(value),None) is not None:
                        self.remember_partial(rewrite(value,surviving,[]))
        yield from candidates

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

    def target_expr(self, target, regs, watch=None, watch_size=1, watch_offset=0):
        ins,expr,start,width=self.access_info(target,regs)
        log(f'[target] 0x{target:X}: {ins.mnemonic} {ins.op_str}')
        log(f'Effective address: 0x{start:X}')
        log(f'Access size: {width} bytes')
        log(f'Access range: 0x{start:X}..0x{start+width-1:X}')
        if watch is None:
            return expr,start
        delta=watch_delta(start,width,watch,watch_size,watch_offset)
        if delta is None:
            raise TraceError('Watch range does not overlap the memory access')
        log(f'Watch address: 0x{watch:X}')
        if watch_size>1 or watch_offset:
            first=watch+watch_offset
            log(f'Watch range: 0x{first:X}..0x{first+watch_size-1:X}')
        log(f'Access offset: {fmt_offset(delta)}')
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

    def remember_partial(self, expr):
        if any(part[0]=='stack' for part in leaves(expr)) and expr not in self.scan_partials:
            self.scan_partials.append(expr)
            self.scan_partials=self.scan_partials[-MAX_PATHS:]

    def trace(self, frames, regs, target, manual_start, watch=None, watch_size=1, watch_offset=0):
        expr,expected=self.target_expr(target,regs,watch,watch_size,watch_offset)
        self.callee_graphs={}
        self.inline_attempts=0
        self.trace_messages=set()
        self.scan_partials=[]
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
                        try:
                            for current in self.rewind(path,snapshots,candidate,(start,),regs if i==0 else None):
                                if entry is not None:
                                    current=rewrite(current,{'rsp':stackaddr(entry)},[])
                                best=current
                                if self.inspect_candidate(current,expected):
                                    self.report(current,expected,True,'Static CFG path candidate')
                                    return True
                                self.remember_partial(current)
                                parts=list(leaves(current))
                                if any(x[0]=='unknown' for x in parts):
                                    continue
                                if any(x[0] in ('reg','stack') for x in parts) and current not in following:
                                    following.append(current)
                                if len(following)>=MAX_PATHS:
                                    break
                        except (TraceError,RecursionError) as error:
                            log(f'[!] Candidate stopped: {error}')
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
        return False

    def trace_recorded(self, history, regs, target, watch=None, watch_size=1, watch_offset=0):
        expr,expected=self.target_expr(target,regs,watch,watch_size,watch_offset)
        self.trace_messages=set()
        self.scan_partials=[]
        log(f'[record] reversing {len(history):,} executed instructions')
        for index in range(len(history)-1,-1,-1):
            self.budget.check('recorded backward trace')
            ins,before=history[index]
            after=history[index+1][1] if index+1<len(history) else regs
            stack={'rsp':stackaddr(before['rsp'])}
            if abs(before['rbp']-before['rsp'])<0x800000:
                stack['rbp']=stackaddr(before['rbp'])
            expr=self.transfer(ins,expr,stack,before,True,after)
        self.remember_partial(expr)
        matched=self.inspect_candidate(expr,expected)
        self.report(expr,expected,matched,'Recorded single-thread path from selected start; other-thread writes not recorded')
        return matched


def watch_delta(start, width, watch, watch_size=1, watch_offset=0):
    if not (0 <= start <= MASK and width > 0 and start+width <= MASK+1):
        raise TraceError('Invalid memory access range')
    first = watch + watch_offset
    if not (0 <= watch <= MASK and watch_offset >= 0 and watch_size > 0 and first+watch_size <= MASK+1):
        raise TraceError('Invalid watch range')
    if start < first+watch_size and first < start+width:
        return watch-start
    return None


def condition(code, flags):
    c,p,z,s,o=(bool(flags&(1<<bit)) for bit in (0,2,6,7,11))
    return {'o':o,'no':not o,'b':c,'c':c,'nae':c,'ae':not c,'nb':not c,'nc':not c,
            'e':z,'z':z,'ne':not z,'nz':not z,'be':c or z,'na':c or z,
            'a':not(c or z),'nbe':not(c or z),'s':s,'ns':not s,'p':p,'pe':p,'np':not p,'po':not p,
            'l':s!=o,'nge':s!=o,'ge':s==o,'nl':s==o,'le':z or s!=o,'ng':z or s!=o,
            'g':not z and s==o,'nle':not z and s==o}.get(code)


@dataclass(frozen=True)
class ScanOptions:
    depth: int
    offset: int
    alignment: int


@dataclass(frozen=True)
class ScanRegion:
    start: int
    end: int
    writable: bool = False
    executable: bool = False


@dataclass(frozen=True)
class ScanTail:
    leading: int = 0
    offsets: tuple = ()
    from_stack: bool = False

    def prepend(self, offset):
        return ScanTail(0, (offset+self.leading,)+self.offsets, self.from_stack)


MAX_SCAN_FRONTIER = 4096
SCAN_BLOCK = 512 * 1024


def split_scan_ranges(regions, modules, preferred, expected):
    writable, deferred, others = [], [], []
    images = sorted(modules,key=lambda module: module.base)
    for region in regions:
        low,high=region.start,region.end
        for module in images:
            start,end=module.base,module.base+module.size
            if end <= low:
                continue
            if start >= high:
                break
            if low < start:
                others.append((not region.writable,low,start))
            rank=(region.executable,module!=preferred)
            (writable if region.writable and not region.executable else deferred).append(
                (rank,max(low,start),min(high,end)))
            low = end
            if low >= high:
                break
        if low < high:
            others.append((not region.writable,low,high))
    others.sort(key=lambda entry: (entry[0],max(0,entry[1]-expected,expected-entry[2])))
    return ([(start,end) for _,start,end in sorted(writable)],
            [(start,end) for _,start,end in sorted(deferred)],
            [(start,end) for _,start,end in others])


def freeze_stack_loads(expr, pm, cache):
    kind=expr[0]
    if kind=='load':
        width,address,_=expr[1:]
        if address[0]=='stack':
            key=(width,address[1])
            if key not in cache:
                try:
                    cache[key]=K(evaluate(expr,pm))
                except Exception:
                    cache[key]=U(f'unreadable stack slot 0x{address[1]:X}')
            return cache[key]
        return L(width,freeze_stack_loads(address,pm,cache))
    if kind in ('reg','stack','const','unknown'):
        return expr
    return B(kind,freeze_stack_loads(expr[1],pm,cache),freeze_stack_loads(expr[2],pm,cache))


def snapshot_scan_seeds(analyzer, expected, budget):
    frontier={expected:ScanTail()}
    cache={}
    for expr in reversed(getattr(analyzer,'scan_partials',())):
        budget.check('stack-derived scan offsets')
        try:
            fixed=freeze_stack_loads(expr,analyzer.pm,cache)
        except Exception:
            continue
        try:
            matches=evaluate(fixed,analyzer.pm)==expected
        except Exception:
            matches=False
        node,leading,offsets=fixed,0,()
        while node[0]=='load' or (node[0]=='add' and node[2][0]=='const'):
            if node[0]=='add':
                leading+=signed(node[2][1])
                node=node[1]
            if node[0]=='load' and node[1]==8:
                # A traced field displacement gives the base even if an
                # earlier owner pointer is still symbolic.
                if matches or not offsets:
                    address=evaluate(node,analyzer.pm) if matches else (expected-leading)&MASK
                    if address:
                        frontier.setdefault(address,ScanTail(leading,offsets,True))
                if not matches:
                    break
                offsets=(leading,)+offsets
                leading=0
                node=node[2]
            elif node[0]!='add':
                break
        if matches and node[0]=='const' and node[1] and offsets:
            frontier.setdefault(node[1],ScanTail(leading,offsets,True))
            if containing(analyzer.modules,node[1]) and analyzer.inspect_candidate(fixed,expected):
                analyzer.report(fixed,expected,True,'Module-root candidate with stack-derived offsets fixed at the breakpoint')
                return None
    if len(frontier)>1:
        log(f'[scan] Added {len(frontier)-1} target address(es) using traced stack-derived offsets')
    return frontier


def scan_blocks(pm, ranges, budget, cross_boundary=False):
    for start, end in ranges:
        for address in range(start, end, SCAN_BLOCK):
            budget.check('pointer scan memory reads')
            size = min(SCAN_BLOCK, end - address)
            inside=min(size+7,end-address)
            extended=min(size+7,MASK+1-address) if cross_boundary else inside
            for amount in dict.fromkeys((extended,inside)):
                try:
                    data=read_exact(pm,address,amount)
                except Exception:
                    continue
                yield address,size,data
                break
            else:
                # A partial read should not drop the other readable pages in this block.
                for page in range(address, address + size, 4096):
                    budget.check('pointer scan page reads')
                    page_size = min(4096, address + size - page)
                    limit=MASK+1 if cross_boundary else end
                    for read_size in dict.fromkeys((min(page_size+7,limit-page),
                                                    min(page_size+7,end-page),page_size)):
                        try:
                            data = read_exact(pm, page, read_size)
                        except Exception:
                            continue
                        yield page, page_size, data
                        break


def scan_links(pm, ranges, frontier, visited, options, budget, phase=None):
    targets = sorted(frontier)
    offset = options.offset
    # Search upper pointer bytes in C, then check the full 64-bit value and signed offset.
    # Coarser prefixes keep the number of full-buffer searches bounded for a wide frontier.
    prefix_bytes = 2
    prefixes = set()
    for shift in (16, 32, 40, 48, 56):
        prefixes = set()
        for target in targets:
            low = max(0, target - offset) >> shift
            high = min(MASK, target + offset) >> shift
            if shift < 56 and high - low >= 8:
                break
            prefixes.update(range(low, high + 1))
            if shift < 56 and len(prefixes) > 8:
                break
        else:
            prefix_bytes = shift // 8
            break
    needles = [prefix.to_bytes(8 - prefix_bytes, 'little') for prefix in sorted(prefixes)]
    scanned=0
    last=time.monotonic()
    for base, size, data in scan_blocks(pm, ranges, budget, options.alignment==1):
        scanned+=size
        if phase and time.monotonic()-last>=2:
            log(f'[scan] {phase}: {scanned / (1024*1024):.1f} MiB read')
            last=time.monotonic()
        for needle in needles:
            hit = data.find(needle, prefix_bytes)
            attempts = 0
            while hit != -1:
                index = hit - prefix_bytes
                if index >= size:
                    break
                slot = base + index
                if slot % options.alignment == 0 and slot not in visited:
                    value = struct.unpack_from('<Q', data, index)[0]
                    next_index = bisect_left(targets, value)
                    choices = targets[max(0, next_index - 1):next_index + 1]
                    target = min(choices, key=lambda address: abs(address - value))
                    if abs(target - value) <= offset:
                        yield slot, frontier[target].prepend(target-value)
                attempts += 1
                if attempts % 4096 == 0:
                    budget.check('pointer scan candidates')
                hit = data.find(needle, hit + 1)


def reverse_pointer_scan(analyzer, regions, expected, options, budget, preferred=None):
    frontier=snapshot_scan_seeds(analyzer,expected,budget)
    if frontier is None:
        return True
    roots, remaining_roots, other_ranges=split_scan_ranges(regions,analyzer.modules,preferred,expected)
    if not roots and not remaining_roots:
        log('[scan] No readable module ranges')
        return False
    log(f'[scan] Searching readable memory; depth={options.depth}, '
        f'max signed offset=0x{options.offset:X}, alignment={options.alignment}')
    visited=set(frontier)
    deferred_targets={}

    def check_roots(ranges,targets,phase,stage_budget):
        for root,tail in scan_links(analyzer.pm,ranges,targets,set(targets),options,stage_budget,phase):
            expr=K(root)
            for offset in tail.offsets:
                expr=B('add',L(8,expr),K(offset))
            if analyzer.inspect_candidate(expr,expected):
                mode=('Reverse scan with stack-derived offsets fixed at the breakpoint'
                      if tail.from_stack else 'Reverse memory scan candidate')
                analyzer.report(expr,expected,True,mode)
                return True
        return False

    primary_budget=Budget(max(0,budget.end-time.monotonic())*0.85) if roots and remaining_roots else budget
    try:
        for depth in range(1, options.depth + 1):
            primary_budget.check('pointer scan depth')
            log(f'[scan] Depth {depth}: {len(frontier):,} target slot(s)')
            deferred_targets.update(frontier)
            if roots and check_roots(roots,frontier,'writable module data',primary_budget):
                return True
            if depth==1 and not roots and remaining_roots:
                if check_roots(remaining_roots,frontier,'readable module regions',primary_budget):
                    return True
                deferred_targets.clear()
            if depth == options.depth:
                break
            following = {}
            for slot,tail in scan_links(analyzer.pm,other_ranges,frontier,visited,options,primary_budget,'non-module regions'):
                following.setdefault(slot,tail)
                if len(following) >= MAX_SCAN_FRONTIER:
                    log(f'[?] Scan frontier capped at {MAX_SCAN_FRONTIER:,} slots')
                    break
            if not following:
                break
            visited.update(following)
            frontier = following
    except TraceError:
        if primary_budget is budget or time.monotonic()<primary_budget.end:
            raise
        log('[scan] Moving to the remaining module regions')
    if remaining_roots and deferred_targets:
        if check_roots(remaining_roots,deferred_targets,'remaining module regions',budget):
            return True
    log('[!] Pointer scan found no matching module-relative chain within its limits')
    return False


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


class MemoryBasicInformation(C.Structure):
    _fields_ = [('base', PTR), ('allocation_base', PTR), ('allocation_protect', DWORD),
                ('partition', C.c_uint16), ('size', C.c_size_t), ('state', DWORD),
                ('protect', DWORD), ('kind', DWORD)]


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
            ('VirtualQueryEx', C.c_size_t, (HANDLE, PTR, C.POINTER(MemoryBasicInformation), C.c_size_t)),
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

    def readable_regions(self, process, budget):
        regions = []
        info = MemoryBasicInformation()
        address = 0
        while address <= MASK:
            budget.check('VirtualQueryEx')
            size = self.VirtualQueryEx(process, address, C.byref(info), C.sizeof(info))
            if not size and C.get_last_error() == 87 and address and regions:
                break
            check(size, 'VirtualQueryEx')
            start = int(info.base or 0)
            end = start + info.size
            if end <= address:
                raise TraceError('VirtualQueryEx returned a non-advancing memory range')
            readable = (info.protect & 0xff) in (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
            if info.state == 0x1000 and readable and not info.protect & 0x100:
                protection=info.protect & 0xff
                writable=protection in (0x04,0x08,0x40,0x80)
                executable=protection in (0x20,0x40,0x80)
                if regions and regions[-1].end==start and (
                    regions[-1].writable,regions[-1].executable)==(writable,executable):
                    regions[-1]=ScanRegion(regions[-1].start,end,writable,executable)
                else:
                    regions.append(ScanRegion(start,end,writable,executable))
            address = end
        return regions

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


def resolve_hit(api, analyzer, regs, target, watch, trace, seconds, scan, value_type):
    expected = watch
    try:
        needs_access = value_type is not None and (expected is None or value_type.size is None)
        if needs_access or (expected is None and scan is not None):
            _, _, start, width = analyzer.access_info(target, regs)
            if expected is None:
                expected = start
        if value_type is not None:
            size = value_type.size if value_type.size is not None else start + width - expected
            value = read_value(analyzer.pm, expected, value_type, size)
            log(f'[value] {value_type.name} at 0x{expected:X} before instruction: {value}')
    except Exception as error:
        if value_type is not None:
            log(f'[!] Could not read {value_type.name}: {error}')
        elif scan:
            log(f'[!] Could not determine scan target: {error}')
    try:
        if trace():
            return True
    except Exception as error:
        log(f'[!] Provenance trace stopped: {type(error).__name__}: {error}')
    if scan and expected is not None:
        budget = Budget(seconds)
        try:
            regions = api.readable_regions(analyzer.pm.process_handle, budget)
            return reverse_pointer_scan(analyzer, regions, expected, scan, budget,
                                        containing(analyzer.modules,target))
        except Exception as error:
            log(f'[!] Pointer scan stopped: {type(error).__name__}: {error}')
    return False


def analyze_hit(api, pm, thread, context, target, manual, seconds, watch=None, scan=None, value_type=None):
    budget = Budget(seconds)
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
    analyzer = ProvenanceAnalyzer(pm, modules, budget)
    watch_range = value_type.watch_range if value_type is not None else (1, 0)
    resolve_hit(api, analyzer, regs, target, watch,
                lambda: analyzer.trace(frames, regs, target, manual, watch, *watch_range), seconds, scan, value_type)


def wait_breakpoint(api, pm, target, manual, seconds, watch=None, scan=None, value_type=None):
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
    watch_range = value_type.watch_range if value_type is not None else (1, 0)

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
                                    delta=watch_delta(start,width,watch,*watch_range)
                                if delta is not None:
                                    finished=True
                                    log(f'[+] Breakpoint hit, TID={event.tid}; skipped {misses} nonmatching hits')
                                    try:
                                        analyze_hit(api,pm,thread,context,target,manual,seconds,watch,scan,value_type)
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


def wait_recorded(api, pm, start, target, manual, seconds, max_steps, record_seconds,
                  watch=None, scan=None, value_type=None):
    """Opt-in single-thread recording, starting BEFORE the desired instruction.
    Every history entry is the instruction and register state before execution.
    The ordinary debugger is used when --record-from is not supplied.
    """
    if start == target:
        return wait_breakpoint(api, pm, target, manual, seconds, watch, scan, value_type)
    original=read_exact(pm,start,1)
    if original==b'\xcc':
        raise TraceError('Recording start already contains INT3')
    pid=api.attach(pm)
    patched=initialized=exited=cancel=False
    tracked=None; history=[]; analyzer=None; deadline=None; tf_original=False
    watch_range = value_type.watch_range if value_type is not None else (1, 0)
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
                                hit=watch_delta(access_start,width,watch,*watch_range) is not None
                                if not hit:
                                    log(f'[filter] recorded hit outside watch: 0x{access_start:X}..0x{access_start+width-1:X}')
                            if hit or cancel or len(history)>=max_steps or time.monotonic()>=deadline:
                                flags(ctx).value=(flags(ctx).value&~0x100)|(0x100 if tf_original else 0)
                                check(api.SetThreadContext(h,ctx),'clear trap flag')
                                tracked=None; finished=True
                                if hit and not cancel:
                                    analyzer.budget=Budget(seconds)
                                    resolve_hit(api, analyzer, before, target, watch,
                                                lambda: analyzer.trace_recorded(history,before,target,watch,*watch_range),
                                                seconds, scan, value_type)
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
    values = [
        ('byte', b'\xff', '255'),
        ('i8', b'\x80', '-128'),
        ('u16', b'\x34\x12', '4660'),
        ('int24', b'\x00\x00\x80', '-8388608'),
        ('4 Bytes', b'\xff' * 4, '4294967295'),
        ('uint48', b'\xff' * 6, str((1 << 48) - 1)),
        ('i64', b'\xff' * 8, '-1'),
        ('u128', b'\xff' * 16, str((1 << 128) - 1)),
        ('u256', b'\x00' * 31 + b'\x80', str(1 << 255)),
        ('bool', b'\x00', 'false'),
        ('bool32', b'\x00\x00\x80\x00', 'true'),
        ('ptr32', b'\x78\x56\x34\x12', '0x12345678'),
        ('ptr', b'\x00\x00\x00\x40\x01\x00\x00\x00', '0x0000000140000000'),
        ('f16', struct.pack('<e', 1.5), '1.5'),
        ('bfloat16', b'\xc0\x3f', '1.5'),
        ('f32', struct.pack('<f', -0.0), '-0.0'),
        ('f64', struct.pack('<d', float('inf')), 'inf'),
        ('f32', bytes.fromhex('00 00 C0 FF'), '-nan'),
        ('f80', bytes.fromhex('00 00 00 00 00 00 00 80 FF 7F'), 'inf'),
        ('f128', bytes.fromhex('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80'), '-0.0'),
        ('ascii[2]', b'A\xff', repr('A\\xff')),
        ('text:cp949[4]', '한글'.encode('cp949'), repr('한글')),
        ('utf8[6]', '한글'.encode('utf-8'), repr('한글')),
        ('utf16[2]', '😀'.encode('utf-16-le'), repr('😀')),
        ('utf32[1]', '😀'.encode('utf-32-le'), repr('😀')),
        ('cutf16[4]', '가\0나'.encode('utf-16-le') + b'\0\0', repr('가')),
        ('wchar', '가'.encode('utf-16-le'), repr('가')),
        ('bytes[3]', b'\x00\xde\xad', '00 DE AD'),
        ('bits[7:4]', b'\x80\x05', '11'),
        ('sbits[7:4]', b'\x80\x05', '-5'),
        ('f32[3]', struct.pack('<3f', 1.5, 2.5, -3.5), '[1.5, 2.5, -3.5]'),
        ('u16[2][2]', struct.pack('<4H', 1, 2, 3, 4), '[[1, 2], [3, 4]]'),
        ('struct:<ifB3x', struct.pack('<ifB3x', -20, 2.5, 1), '(-20, 2.5, 1)'),
        ('struct:<h[2]', struct.pack('<2h', -2, 1), '[(-2,), (1,)]'),
    ]
    for name, data, expected in values:
        spec = parse_value_type(name)
        assert spec.size == len(data), (name, spec.size, len(data))
        assert spec.decode(data) == expected, (name, spec.decode(data), expected)
    extended = bytes.fromhex('00 00 00 00 00 00 00 A0 FF 3F')
    assert Decimal(parse_value_type('f80').decode(extended)) == Decimal('1.25')
    quad = ((16383 << 112) | 1).to_bytes(16, 'big')
    assert Decimal(parse_value_type('f128', 'big').decode(quad)) > 1
    assert Decimal(parse_value_type('f128').decode((1).to_bytes(16, 'little'))) > 0
    assert parse_value_type('i24', 'big').decode(b'\x80\x00\x00') == '-8388608'
    assert parse_value_type('bf16', 'big').decode(b'\x3f\xc0') == '1.5'
    assert parse_value_type('utf16[2]', 'big').decode('한글'.encode('utf-16-be')) == repr('한글')
    assert parse_value_type('struct:HI', 'big').decode(struct.pack('>HI', 1, 2)) == '(1, 2)'
    field = parse_value_type('bits[16:1]')
    assert field.watch_range == (1, 2)
    assert watch_delta(0x4000, 1, 0x4000, *field.watch_range) is None
    assert watch_delta(0x4002, 1, 0x4000, *field.watch_range) == -2
    assert parse_value_type('bits[16:1]', 'big').watch_range == (1, 0)
    assert parse_value_type('none') is None
    assert parse_value_type('auto').decode(b'\x01\xab') == '01 AB'
    assert 'float32=1.5' in parse_value_type('all').decode(struct.pack('<f', 1.5))
    for bad in ('i7', 'u0', 'bytes[0]', 'u8[0]', 'auto[8]', 'bits[4:0]', 'struct:', 'text:bogus[8]'):
        try:
            parse_value_type(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f'Accepted invalid value type: {bad}')
    log('[PASS] scalar, endian, extended float, bytes, text, bit fields, arrays, and struct formats')

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
    assert C.sizeof(MemoryBasicInformation) == 48 and MemoryBasicInformation.size.offset == 24
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
    assert watch_delta(0x4120,16,0x411e,4)==-2
    assert watch_delta(0x4120,16,0x411c,4) is None
    assert watch_delta(0x4123,1,0x4120,4)==-3
    assert watch_delta(0x4124,1,0x4120,4) is None
    output=StringIO()
    with redirect_stdout(output):
        assert MockAnalyzer().trace(frames,{'rcx':0x4000},target,None,0x411e,4)
    captured=output.getvalue()
    assert 'Chain: [[example.exe+0x800]+0x30]+0x11E' in captured,captured
    assert 'Access offset: -0x2' in captured,captured
    assert 'Expected: 0x411E' in captured,captured
    try:
        MockAnalyzer().target_expr(target,{'rcx':0x4000},0x4130)
    except TraceError:
        pass
    else:
        raise AssertionError('Out-of-range watch accepted')
    log('[PASS] SIMD, partial typed ranges, byte writes inside wider values, and exact start addresses')


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

    # A completed call supplies RAX to a SIMD store. The first RET path has
    # another result; only the second agrees with the watched byte at +4.
    target=f1+9
    pm.ptrs={root:0x2000,0x2030:0x4000}
    owner=FakeInsn(f1,'mov','rcx, [rip + owner]',(reg('rcx'),mem('rip',root-(f1+4))),('rcx',))
    direct=FakeInsn(f1+4,'call','getter',(imm(f0),),('rsp',),5)
    store=FakeInsn(target,'movups','[rax], xmm0',(mem('rax',0,size=16,access=2),reg('xmm0',16)))
    getter=[FakeInsn(f0,'jne','other',(imm(f0+12),),jump=True),
            FakeInsn(f0+4,'lea','rax, [rcx + 0x40]',(reg('rax'),mem('rcx',0x40)),('rax',)),
            FakeInsn(f0+8,'ret','',(),('rsp',),1,ret=True),
            FakeInsn(f0+12,'mov','rax, [rcx + 0x30]',(reg('rax'),mem('rcx',0x30)),('rax',)),
            FakeInsn(f0+16,'ret','',(),('rsp',),1,ret=True)]
    insns={ins.address:ins for ins in [owner,direct,store]+getter}
    frames=[{'rip':target,'rsp':0x8010}]
    output=StringIO()
    with redirect_stdout(output):
        assert MockAnalyzer().trace(frames,{'rax':0x4000},target,None,0x4004)
    captured=output.getvalue()
    assert 'Chain: [[example.exe+0x800]+0x30]+0x4' in captured,captured
    assert '-> 0x2044' in captured and 'Expected: 0x4004' in captured,captured
    log('[PASS] static direct CALL through two RET paths to exact SIMD watch at +4')

    # IAT-like CALL into a tail thunk; the final leaf has no unwind entry.
    thunk_ptr,leaf_ptr=root+8,root+16
    pm.ptrs.update({thunk_ptr:f0,leaf_ptr:f2})
    indirect=FakeInsn(f1+4,'call','qword ptr [rip + target]',
                      (mem('rip',thunk_ptr-(f1+9)),),('rsp',),5)
    thunk=FakeInsn(f0,'jmp','qword ptr [rip + leaf]',
                   (mem('rip',leaf_ptr-(f0+4)),),jump=True)
    leaf=[FakeInsn(f2,'mov','rax, [rcx + 0x30]',(reg('rax'),mem('rcx',0x30)),('rax',)),
          FakeInsn(f2+4,'ret','',(),('rsp',),1,ret=True)]
    insns={ins.address:ins for ins in [owner,indirect,store,thunk]+leaf}
    output=StringIO()
    with redirect_stdout(output):
        a=MockAnalyzer()
        find=a.table.find
        a.table.find=lambda address: None if address==f2 else find(address)
        assert a.trace(frames,{'rax':0x4000},target,None,0x4004)
    assert 'Chain: [[example.exe+0x800]+0x30]+0x4' in output.getvalue(),output.getvalue()
    log('[PASS] indirect CALL and tail JMP into a leaf without .pdata')

    # The callee writes a caller-owned stack slot passed by address.
    pm.ptrs[root]=0x4000
    target=f1+17
    out_path=[FakeInsn(f1,'mov','rdx, [rip + root]',(reg('rdx'),mem('rip',root-(f1+4))),('rdx',)),
              FakeInsn(f1+4,'lea','rcx, [rsp + 0x28]',(reg('rcx'),mem('rsp',0x28)),('rcx',)),
              FakeInsn(f1+8,'call','writer',(imm(f0),),('rsp',),5),
              FakeInsn(f1+13,'mov','rax, [rsp + 0x28]',(reg('rax'),mem('rsp',0x28)),('rax',)),
              FakeInsn(target,'movups','[rax], xmm0',(mem('rax',0,size=16,access=2),reg('xmm0',16))),
              FakeInsn(f0,'mov','[rcx], rdx',(mem('rcx',0,access=2),reg('rdx'))),
              FakeInsn(f0+4,'ret','',(),('rsp',),1,ret=True)]
    insns={ins.address:ins for ins in out_path}
    output=StringIO()
    with redirect_stdout(output):
        a=MockAnalyzer()
        assert a.trace([{'rip':target,'rsp':0x8010}],{'rax':0x4000},target,None,0x4004)
    assert 'Chain: [example.exe+0x800]+0x4' in output.getvalue(),output.getvalue()
    log('[PASS] static CALL through a by-reference stack output')

    # The caller constructs a stack object and passes its address in a
    # register. Rewinding the LEA must let the earlier member store alias.
    stack_path=[FakeInsn(f0,'mov','[rsp + 0x68], rcx',(mem('rsp',0x68,access=2),reg('rcx'))),
                FakeInsn(f0+4,'lea','r14, [rsp + 0x50]',(reg('r14'),mem('rsp',0x50)),('r14',))]
    a=MockAnalyzer()
    stack_states,_=a.stack_coordinates(stack_path,0x8008)
    with redirect_stdout(StringIO()):
        result=list(a.rewind(stack_path,stack_states,L(8,B('add',R('r14'),K(0x18)))))
    assert result==[R('rcx')],result
    log('[PASS] stack object LEA normalizes before matching the earlier member store')

    # Conditional dataflow must preserve both possible definitions.
    conditional=FakeInsn(f0+4,'cmovne','rax, rcx',(reg('rax'),reg('rcx')),('rax',))
    with redirect_stdout(StringIO()):
        assert set(MockAnalyzer().rewind([conditional],[{}],R('rax')))=={R('rax'),R('rcx')}
    log('[PASS] both static CMOV paths retained')

    class ScanMemory:
        process_handle=1

        def __init__(self, blocks):
            self.blocks=blocks

        def read_bytes(self, address, size):
            for start,data in self.blocks:
                if start<=address and address+size<=start+len(data):
                    return bytes(data[address-start:address-start+size])
            raise ValueError(f'unmapped 0x{address:X}')

    image, heap, watched=bytearray(64),bytearray(64),bytearray(64)
    struct.pack_into('<Q',image,8,0x7070)
    struct.pack_into('<Q',heap,0x20,0x4000)
    struct.pack_into('<f',watched,4,123.5)
    a=MockAnalyzer()
    a.pm=ScanMemory([(root,image),(0x7040,heap),(0x4000,watched)])
    a.modules=[Module('example.exe',base,0x1000)]
    api=NS(readable_regions=lambda process,budget: [ScanRegion(0x4000,0x4040,True),
           ScanRegion(0x7040,0x7080,True),ScanRegion(root,root+64,True)])

    def unresolved_trace():
        raise TraceError('unresolved instruction')

    output=StringIO()
    with redirect_stdout(output):
        assert resolve_hit(api,a,{},target,0x4004,unresolved_trace,10,ScanOptions(2,0x10,8),parse_value_type('f32'))
    captured=output.getvalue()
    assert 'Chain: [[example.exe+0x808]-0x10]+0x4' in captured,captured
    assert 'before instruction: 123.5' in captured,captured
    log('[PASS] failed symbolic trace falls back to signed two-hop scan and reads float32')

    output=StringIO()
    with redirect_stdout(output):
        assert resolve_hit(api,a,{'rax':0x4000},target,0x4004,lambda:True,10,None,parse_value_type('auto'))
    assert 'auto at 0x4004 before instruction: 00 00 F7 42' in output.getvalue(),output.getvalue()
    utf16 = parse_value_type('cutf16[16]')
    text_memory=ScanMemory([(0x9000,'가\0'.encode('utf-16-le'))])
    assert read_value(text_memory,0x9000,utf16,utf16.size)==repr('가')
    log('[PASS] automatic access-sized raw read and short NUL-terminated string before unreadable memory')

    # The watch is in a selected slab 0x46AC bytes past its page base.
    # The physical module pointer only reaches the table owner.
    owner_address,table_address,slab=0x260000,0x300000,0x500000
    owner_bytes,table_bytes,stack_bytes=bytearray(0x60),bytearray(0x40),bytearray(0x30)
    struct.pack_into('<Q',stack_bytes,0,504)
    struct.pack_into('<Q',stack_bytes,0x28,owner_address)
    struct.pack_into('<Q',owner_bytes,0x50,table_address)
    struct.pack_into('<Q',table_bytes,0x18,slab)
    struct.pack_into('<Q',image,8,owner_address-0x20)
    index=B('sub',L(8,stackaddr(0x9000)),K(1))
    offset=B('mul',B('and',index,K(0x7f)),K(0x98))
    for owner in (L(8,stackaddr(0x9028)),R('rdi')):
        page=L(8,B('add',L(8,B('add',owner,K(0x50))),B('mul',B('shr',index,K(7)),K(8))))
        partial=B('add',B('add',page,offset),K(4))
        a.scan_partials=[partial]
        if owner==R('rdi'):
            ins=FakeInsn(f0,'nop','')
            with redirect_stdout(StringIO()):
                list(a.rewind([ins],[{}],partial,live={'rdi':owner_address}))
            assert len(a.scan_partials)==2,a.scan_partials
        a.pm=ScanMemory([(root,image),(0x9000,stack_bytes),(owner_address,owner_bytes),
                         (table_address,table_bytes)])
        regions=[ScanRegion(base,base+0x800,False,True),ScanRegion(root,root+64,True)]
        output=StringIO()
        with redirect_stdout(output):
            assert reverse_pointer_scan(a,regions,slab+0x46ac,ScanOptions(1,0x2000,8),Budget(5),a.modules[0])
        captured=output.getvalue()
        assert 'Chain: [[[example.exe+0x808]+0x70]+0x18]+0x46AC' in captured,captured
        assert 'offsets fixed at the breakpoint' in captured,captured
    log('[PASS] indexed slab scan from a stack spill or preserved register, beyond the generic offset limit')

    block=bytearray(SCAN_BLOCK+8)
    struct.pack_into('<Q',block,SCAN_BLOCK-3,0x12350002)
    memory=ScanMemory([(0,block)])
    links=[(SCAN_BLOCK-3,ScanTail(0,(-4,)))]
    for ranges in ([(0,len(block))],[(0,SCAN_BLOCK),(SCAN_BLOCK,len(block))]):
        for alignment,expected_links in ((1,links),(8,[])):
            actual_links=list(scan_links(memory,ranges,{0x1234fffe: ScanTail()},set(),
                                         ScanOptions(1,4,alignment),Budget(10)))
            assert actual_links==expected_links,actual_links
    log('[PASS] unaligned scan across read blocks and pointer-value prefix boundaries')

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
        vector_store=next(actual.md.disasm(bytes.fromhex('0F 11 00'),0x1000,count=1))
        actual.instruction=lambda address: vector_store
        with redirect_stdout(StringIO()):
            expr,expected=actual.target_expr(0x1000,{'rax':0x4000},0x4004,4)
        assert expected==0x4004 and evaluate(expr,pm,{'rax':0x4000})==0x4004
        log('[PASS] real Capstone bytes: stack spill/reload + SIB LEA')
        log('[PASS] real Capstone bytes: float32 watch at +4 inside MOVUPS')


def main():
    parser = argparse.ArgumentParser(description='x64 pointer chain candidate tracer')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--timeout', type=float, default=30, help='seconds per analysis stage, excluding breakpoint wait')
    parser.add_argument('--record-from', type=lambda x:int(x,16), help='hex address at which to begin single-step history')
    parser.add_argument('--watch', type=lambda x:int(x,16), help='exact data address (hex); omit to prompt')
    parser.add_argument('--max-steps', type=int, default=20000)
    parser.add_argument('--record-timeout', type=float, default=60)
    parser.add_argument('--no-scan', action='store_true', help='disable the reverse memory scan after an unresolved trace')
    parser.add_argument('--scan-depth', type=int, default=6, help='maximum dereferences in a scan candidate (default: 6)')
    parser.add_argument('--scan-offset', type=lambda x: int(x, 0), default=0x2000,
                        help='maximum absolute offset per scan step (default: 0x2000)')
    parser.add_argument('--scan-unaligned', action='store_true', help='also scan pointers stored at non-8-byte-aligned addresses')
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument('--type', dest='value_format', metavar='FORMAT',
                         help='watched value type (default: auto); see --list-types')
    formats.add_argument('--float32', dest='value_format', action='store_const', const='f32',
                         help='alias for --type f32')
    parser.set_defaults(value_format='auto')
    parser.add_argument('--endian', choices=('little', 'big'), default='little',
                        help='byte order for value decoding (default: little)')
    parser.add_argument('--list-types', action='store_true', help='show available value formats')
    args = parser.parse_args()
    if args.list_types:
        print(VALUE_FORMATS, end='')
        return
    if args.self_test:
        self_test()
        return
    try:
        value_type = parse_value_type(args.value_format, args.endian)
    except (ValueError, RecursionError, OverflowError) as error:
        parser.error(str(error))
    if os.name != 'nt' or C.sizeof(PTR) != 8:
        raise SystemExit('Windows x64 and 64-bit Python required')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('--timeout must be positive')
    if args.max_steps <= 0 or not math.isfinite(args.record_timeout) or args.record_timeout <= 0:
        parser.error('record limits must be positive')
    if args.scan_depth <= 0 or not 0 <= args.scan_offset <= MASK:
        parser.error('--scan-depth must be positive and --scan-offset must be an unsigned 64-bit value')
    scan = None if args.no_scan else ScanOptions(args.scan_depth, args.scan_offset, 1 if args.scan_unaligned else 8)
    import pymem
    api = WinAPI()
    log('========== POINTER CHAIN FINDER ==========')
    name = input('Process name or PID: ').strip()
    target = int(input('Breakpoint address (hex): ').strip(), 16)
    watch=args.watch
    if watch is None:
        watch_text=input('Watch address (hex, Enter = access start): ').strip()
        watch=int(watch_text,16) if watch_text else None
    if watch is not None:
        watch_size = (value_type.size or 1) if value_type is not None else 1
        if not 0 <= watch <= MASK or watch+watch_size > MASK+1:
            raise TraceError('Invalid watch range for the selected value type')
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
            wait_breakpoint(api, pm, target, manual, args.timeout, watch, scan, value_type)
        else:
            wait_recorded(api, pm, args.record_from, target, manual, args.timeout,
                          args.max_steps, args.record_timeout, watch, scan, value_type)
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
