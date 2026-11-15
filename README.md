# Pointer Chain Finder

A Python-based pointer chain analyzer for Windows x64 applications, powered by **Pymem**, **Capstone**, and the Windows Debugging API.

Unlike traditional pointer scanners, this tool traces assembly instructions backward and walks through call stack frames to discover module-relative pointer chains.

## Features

- Automatic breakpoint handling
- Backward assembly instruction tracing
- Automatic function boundary detection
- Cross-function call stack analysis
- Stack slot and register tracking
- SIB addressing support
- Static control flow analysis
- Dynamic instruction recording
- SIMD memory access range detection
- Automatic pointer offset correction
- Pointer chain validation

## Requirements

- Windows x64
- Python 3.10+ (64-bit)
- Pymem
- Capstone

## Installation

```bash
pip install pymem capstone
```

## Usage

```bash
python main_v5.py
```

Enter the following information when prompted:

| Input | Description |
|---|---|
| Process name or PID | Target process |
| Breakpoint address | Instruction address in hexadecimal |
| Watch address | Optional exact memory address to track |
| Function start | Optional function start address (Enter for automatic detection) |

Instruction addresses discovered using Cheat Engine's **Find out what accesses this address** or **Find out what writes to this address** can be used as breakpoint addresses.

## Example Output

```text
========== POINTER CHAIN ==========
Chain: [[[example.exe+0x123456]+0x30]+0x48]+0x128
Expected: 0x1234567890
[+] Address matched (module-relative candidate)
[+] Debugger detached
```

## Command-Line Options

| Option | Description |
|---|---|
| `--watch` | Specify the exact memory address to track |
| `--timeout` | Set the analysis timeout |
| `--record-from` | Enable dynamic instruction recording from a specified address |
| `--max-steps` | Set the maximum number of recorded instructions |
| `--record-timeout` | Set the instruction recording timeout |
| `--self-test` | Run built-in tests |

## How It Works

1. Attach to the target process.
2. Wait for the specified breakpoint.
3. Capture registers and call stack frames.
4. Trace assembly instructions backward across function boundaries.
5. Resolve a module-relative pointer chain candidate.
6. Validate the chain against the target memory address.

## Limitations

- Only Windows x64 is supported.
- Not all x86-64 instructions are supported.
- Static analysis may produce multiple possible paths.
- A successful address match does not guarantee pointer stability across process restarts.

## Disclaimer

This project is intended for educational purposes, debugging, and authorized reverse engineering. Use it only on software you own or have permission to analyze.

-# AI Generated
