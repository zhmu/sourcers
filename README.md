# SourceRs

## Example

```sh
> ndisasm -b 32 test/t1.bin
00000000  A014000000        mov al,[0x14]
00000005  668B1D15000000    mov bx,[dword 0x15]
0000000C  8B0D17000000      mov ecx,[dword 0x17]
00000012  EB07              jmp short 0x1b
00000014  0102              add [edx],eax
00000016  0003              add [ebx],al
00000018  0000              add [eax],al
0000001A  00CD              add ch,cl
0000001C  20                db 0x20
> cargo run -- --format=map --bits=32 t1.bin
[...]
0000  a014000000            mov  al,byte ptr [data_0014]
0005  668b1d15000000        mov  bx,word ptr [data_0015]
000c  8b0d17000000          mov  ecx,dword ptr [data_0017]
0012  eb07                  jmp  loc_001b

data_0014:
0014  01                    db    1
data_0015:
0015  0200                  dw     2
data_0017:
0017  03000000              dd       3
loc_001b:
001b  cd20                  int  20h
[...]
```

## Introduction

In the early to mid '90ies, Sourcer was one of my tools of choice. Given some binary executable file as input, it would generate an assembly listing. This listing could be further analyzed and annotated using a text editor.

In time, Sourcer has been eclipsed by tools like [IDA](https://hex-rays.com/) and [Ghidra](https://ghidra-sre.org/). These allow an interactive experience, which is important for today's reverse engineering tools as binaries are getting very large and usually the focus is only on individual parts rather than everything.

However, at times, I like analyzing a binary and having a byte-accurate reimplementation, for example [Sierra's sound drivers](https://github.com/zhmu/sierra-reenigne/tree/main/sound/drivers) and [Novell's NetWare DOS client](https://github.com/zhmu/nw-reenigne/tree/main/vlm). I enjoy incrementally improving the assembly file to generate a identical or equivalent binary and always found Sourcerer a useful tool.

As  Sourcerer is no longer sold or maintained, and the parent company V-Communications seems to have disappeared. I decided to try to reimplement a similar tool in the [Rust](https://www.rust-lang.org/) programming language, leveraging the excellent [Capstone](https://www.capstone-engine.org/) disassembly framework.

## Status

This project is in its early stages. Some highlights:

* Capable of processing single-segment 16/32/64-bit binaries
* Identifies code and data locations

Of course, this tool will never be perfect - some guesswork is to be expected - but if you'd like to contribute, I accept pull requests!

## License

GPLv3

