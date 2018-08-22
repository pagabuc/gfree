## GFree
This is a LLVM-based implementation of
[GFree](https://seclab.ccs.neu.edu/static/publications/acsac2010rop.pdf) for Intel x86-64.

In the next paragraphs i will shortly recap all the transformation
GFree applies to produce gadget-less binaries, but i still suggest you
to read the original paper (anyway, the installer needs to build a
fresh installation of LLVM, so you will probably have time even for a
coffee! )

This is the implementation status of the features presented in the paper:

- [x] Alignment Sleds 
- [x] Return Address Protection
- [x] Frame Cookies
- [x] Register Reallocation
- [x] Instruction Transformation
- [ ] Jump Offset Adjustments
- [x] Immediate and Displacement Reconstructions
- [ ] Inter-Instruction Barrier


#### tl;dr
```
bash install.sh
jmp FAQ
```

### What do we want? 

We want to reduce (or ideally eliminate) the possibility of an
attacker to mount a Return Oriented Programming (ROP) or Jump Oriented
Programming (JOP) attack. Those attacks are based on gadgets: short
pieces of code that firstly execute a small task (i.e. load an
immediate in a register) and then pass the control to another
gadget. Given this definition we can divide a gadget in two logical
sections, the *code* and the *linking* section. The first part is the
one that executes the task, while the second one chains two gadgets
together. The very end of the linking section has to be a *free-branch*
instruction, i.e. an instruction that changes the control flow of the
program. GFree's interest is in these free-branch instructions, since
if we remove them, we break {R,J}OP. Sounds fair enough, ain't it?

### How we can do it

Long story short, ROP uses `ret` and JOP uses `call *` and `jmp *` to
chain gadgets together. 

```
+---+---+---+---+---+---+---+---+
|   Encoding    |  Instruction  |
+---+---+---+---+---+---+---+---+
| 0xc{2,3,a,b}  |      ret      |
+---+---+---+---+---+---+---+---+
| 0xff 0xXX     |  jmp*/call*   |
+---+---+---+---+---+---+---+---+
Free-branch instructions for ROP and JOP
```

Unfortunately for us, free-branch instructions can be found both in an
aligned way (i.e `ret` at the end of a function) and in an unaligned
one (i.e `ret` inside `mov %rax,0xaaC3aa`) since the Intel
architecture does not force any execution alignment for instructions.
GFree handles both cases with two different sets of techniques:
unaligned gadgets are *removed* and aligned ones are *protected*.


## Unaligned free-branch

An unaligned free-branch lives inside an instruction.  The first step
in order to remove them is to understand the semantic of the different
fields that compose an instruction. This is covered pretty well by the
Intel Manual, but here's a summary of the Intel instruction format:

```
+---+---+---+---+---+---+---+----+---+---+---+---+---+---+---+----+
|  PREFIXES |  OPCODE   |  MODR/M + SIB  |  OFFSET   | IMMEDIATE  | 
+---+---+---+---+---+---+---+----+---+---+---+---+---+---+---+----+
                       Intel Instruction Format
```

Each of this field require it's own specific technique, in order to
remove the free-branch that lives in there. All the techniques we
propose are implemented as LLVM backend Passes.

#### Immediate & Offset

The immediate and offset reconstruction pass
(`X86GFreeImmediateRecon.cpp`) is hooked before the register allocation
(addPreRegAlloc). It replaces an "evil" instruction with multiple
"safe" instructions, which preserve the semantic but don't
contain any unaligned gadget.

Since an example is worth thousands words, the following instruction

```
05 aa C3 00 00     add   eax,0xc3aa
```
is rewritten to

```
bb aa 03 00 00     mov    ebx,0x3aa
81 cb 00 c0 00 00  or     ebx,0xc000
01 d8              add    eax,ebx
```

and the 0xc3 is successfully removed!

Offsets are handled in a similar way. For example,
`67 89 98 ff C3 00 00   mov DWORD PTR [eax+0xc3ff],ebx` is translated into:
```
b9 ff c0 00 00     mov    ecx,0xc0ff
81 c9 00 03 00 00  or     ecx,0x300
01 c8              add    eax,ecx
67 89 18           mov    DWORD PTR [eax],ebx
29 c8              sub    eax,ecx
```

The current implementation handles also some corner cases where EFLAGS
must be preserved, by pushing/popping it to/from the stack.

#### ModR/M + SIB

The ModR/M and SIB fields specify the format of the operands of an
instruction. So, for example, in `89 d8 mov eax,ebx` the value 0xd8
tells the first register is `eax` and the second is `ebx`.  Similarly
0xca in `67 8d 44 ca 08 lea eax,[edx+ecx*8+0x8]` indicate that the base is
`edx` and the index is `ecx*8`.

The pass to handle this cases (`X86GFreeModRMSIB.cpp`) is hooked after
the register allocation but before the register rewriting. At this
point, the MachineInstructions (*MIs*) are
still written with virtual registers but a map (VirtualRegisterMap)
contains - for each virtual register - the allocated physical
register. The first way to remove an unaligned free-branch is to
reallocate a virtual register in such a way the ModRM field became
"safe". The reallocation must be done without breaking the existing
live intervals... using a physical register which is alive where the
instruction is, is definitely not a good idea!

To understand if a register reallocation correctly sanitize the
instruction, we wrote an assembler from MachineInstr to bytes
(`X86GFreeAssembler.cpp`). The process is iterative, we simply try all
the available registers.

If a register can not be found, the ~~dirty~~fallback solution
kicks in. As usual, code talks more than words, so:

```
00 c3      add  bl,al
```

is transformed by the fallback solution in

```
41 55      push   r13
41 88 dd   mov    r13b,bl
41 00 c5   add    r13b,al
44 88 eb   mov    bl,r13b
41 5d      pop    r13
```


#### Prefixes

No prefixes contains evil bytes, and the only two instruction whose
opcode can be malicious are: `movnti` and `bswap`. 

## Aligned Free-Branch

Aligned free-branch are those that normally live in a program and
that cannot be removed. For example: `ret` at the end of a
function, or `call eax` inside a function. GFree adopts two different
techniques to protect them.

#### Return Address Protection 

To protect aligned `ret`, the entry point of every function is
instrumented with a routine that encrypts the saved return
address. This routine is a xor between the return address
and a random key (taken from fs:0x28):
```
64 4c 8b 1c 25 28 00 00 00   mov    %fs:0x28,%r11
4c 31 1c 24                  xor    %r11,(%rsp)
	 
```

Symmetrically each exit point is instrumented with a decryption
routine that xores again the saved return address with fs:0x28:

```
64 4c 8b 1c 25 28 00 00 00   mov    %fs:0x28,%r11
4c 31 1c 24                  xor    %r11,(%rsp)
c3                           retq
``` 

This protection works because, without knowing the content of fs:0x28,
the attacker is not able to forge valid return address.

Moreover, each decryption routine is prepended with a sled of 9
nops. This ensures the routine will be executed from start to end, not
matter what was the execution alignment before.

The Return Address Protection is implemented in `X86GFree.cpp`.

#### Jump Control Protection

The protection scheme for *indirect calls* and *jumps* is based on a
random cookie pushed on the stack. Every function - that contains at
least one instance of these instructions - is instrumented with a
header that compute a xor of a non secret random integer and a secret
key:

```
49 bb 47 b8 1f 44 ee 03 97 52  movabs $0x529703ee441fb847,%r11
64 4c 33 1c 25 28 00 00 00     xor    %fs:0x28,%r11
4c 89 5d d0                    mov    %r11,-0x30(%rbp)
	
```
This value is then checked before every indirect transfer:
```
49 bb 47 b8 1f 44 ee 03 97 52  movabs $0x529703ee441fb847,%r11
4c 33 5d d0            	       xor    -0x30(%rbp),%r11
64 4c 3b 1c 25 28 00 00 00     cmp    %fs:0x28,%r11
0f 84 01 00 00 00              je     400638 <main+0x98>
f4                             hlt
ff 55 e8                       callq  *-0x18(%rbp)
```

If the check fails the function has not been executed from the very
beginning. This means the attacker jumped in the middle of it and the
indirect transfer is denied by GFree. Also in this case, the routine
is prepended with a sled of 9 nops.
    
The Jump Control Protection is implemented in `X86GFreeJCP.cpp`.

### Overhead

Phoronix Test Suite v6.2.2:

Program                         | Clang Native | Clang G-Free  |  Overhead (%)  |
------------------------------  | -----------  | ------------  | -------------- |
Gcrypt Library                  |1518          |1602           |  5.55          |
John The Ripper                 |4966          |4521           |  8.96          |
John The Ripper                 |16937167      |15708667       |  7.25          |
John The Ripper                 |70871         |53494          | 24.52          |
x264                            |155.70        |132.05         | 15.19          |
7-Zip Compression               |21172         |18983          | 10.34          |
Parallel BZIP2 Compression      |10.43         |11.01          |  5.56          |
Gzip Compression                |11.55         |11.59          |  0.35          |
LZMA Compression                |332.14        |334.47         |  0.70          |
Monkey Audio Encoding           |5.55          |5.86           |  5.59          |
FLAC Audio Encoding             |8.13          |8.01           | -1.48          |
LAME MP3 Encoding               |13.04         |13.18          |  1.07          |
Ogg Encoding                    |7.21          |7.37           |  2.22          |
WavPack Audio Encoding          |8.87          |9.03           |  1.80          |
FFmpeg                          |11.27         |11.63          |  3.19          |
GnuPG                           |7.62          |7.59           | -0.39          |
Mencoder                        |21.23         |22.43          |  5.65          |
OpenSSL                         |543.13        |532.30         |  1.99          |


A more detailed version of the results is available [here](http://www.s3.eurecom.fr/~pagabuc/gfree/benchmark.html)


### Evaluation

The current implementation is able to compile medium-size applications such as:
coreutils, apache, ffmpeg, gzip, lame, openssl, sqlite, util-linux, wireshark, evince.
It also passes *all* the tests included in the aforementioned programs.

The table compares the amount of gadgets with and without GFree.

Program         | Clang-GFree | Clang  |   %   |
--------------  | ----------- | -----  | ----- |
gzip            | 415         | 995    | 58.0  |
httpd           | 2992        | 5852   | 48.8  |
lame            | 1771        | 4586   | 61.3  |
libxml2         | 6567        | 26295  | 75.0  |
coreutils(ls)   | 545         | 1133   | 51.8  |
openssl         | 19741       | 35916  | 45.0  |
sqlite3         | 3650        | 11285  | 67.6  |
**TOTAL**       | 35681       | 86062  |**58.5**|


If you are wondering why the column of Clang-GFree is not zero, please
go ahead and read the TODO.


### TODO

Contributions are very welcome. The next big step for the project is
to avoid the introduction of new gadgets from the linker, when it
applies relocations. In my mind, iteratively adding nops here and there should
converge but i feel it might exists a less lazy and more optimized way to solve
this problem ;-)

There are also small fixes like adding support for floating point
registers in the register reallocation, extending the immediate
reconstruction to any missing instructions (i.e. IMUL64rri.) and
emitting optimized nops (instead of "nop"*9 emit "nop word [rax+rax+0x0]").

Last but not least, offset of relative jumps are calculated during
compilation and they can introduce new gadgets as well. I currently
have a (somewhat) working implementation of it, so tell me if you want
to complete the job!

### CONTACT

If you are interested working on GFree, please ping me!

Mail: python -c "print 'pa%s%seurecom.%s' % ('gani', '@', 'fr')"

Twitter: @pagabuc

IRC: pagabuc on Freenode