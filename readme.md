# rop-chainer

rop-chainer is a simple tool that finds gadgets and creates gadget chains for 32-bit ELF binaries. It uses the (capstone)[https://github.com/aquynh/capstone] framework for disassembling byte sequences obtained by backtracking from located `ret` instructions.

## Usage

```
usage: rop.py [-h] [--depth <depth>] [--chain] <binary>

positional arguments:
  <binary>         filename of binary

optional arguments:
  -h, --help       show this help message and exit
  --depth <depth>  depth of search for gadgets
  --chain          enable chain generation
```

## Output

```
Ret-gadgets:
...
0x8117e54: pop eax ; ret
...
Syscall-gadgets:
...
0x804d1b0: syscall
...
Summary:
Found 1497 ret-gadgets!
Found 7 syscall-gadgets!
Strings:
...
Collecting gadgets for ropchain:
...
Generated chain:
'q\xc3\x12\x08`S\x13\x08 4\x13\x08/bin\x1c
%\x0b\x08q\xc3\x12\x08dS\x13\x08 4\x13
x08// \sh\x1c\%\x0b\x08q\xc3\x12\x08hS
x13\x08XZ\x07\x08\xef\xbe\xad\xde\xef
\xbe\xad\xde\x1c%\x0b\x08u\xff\x05
\x08`S\x13\x08q\xc3\x12\x08hS\x13\x08
4\x13\x08hS\x13\x08\xcc\r\x06\x08hS
\x13\x08|xae\x04\x08|\xae\x04\x08|\xae
\x04\x08|\xae\x04\x08|\xae\x04\x08|
\xae\x04\x08|\xae\x04\x08|\xae
\x04\x08|\xae\x04\x08|\xae\x04\x08|
\xae\x04\x08\xb0\xd1\x04\x08'
```