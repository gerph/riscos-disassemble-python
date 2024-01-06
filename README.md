# RISC OS disassembly in Python

## Introduction

This repository contains the module used to disassemble ARM and Thumb code
for RISC OS Pyromaniac. It uses the Capstone library to do so, but modifies
the output so that the disassembly is in a form which is generally seen by
RISC OS users.


## Requirements

The disassembly code requires the Capstone library to be installed. Capstone
4 is currently recommended, although later versions may function as well.

```
pip install 'capstone<5'
```


## Usage

To use this in another project you would usually need to import the module
and subclass the `Disassemble` class to add functions necessary to access
memory and registers, and to decode SWI calls. However, if you do not care
about these things, the simplest usage can be found in the example script
`simple_disassemble.py`.

A more advanced version, which allows context colouring is provided as
a tool within the module. To use it, use:

    python -m riscos_disassemble <file>

Use `--thumb` to disassemble Thumb code.

Use `--colour` or `--colour-8bit` for coloured output using the primary
colours, or the 8bit colour palette.


## Example

The `hello_world` utility file (suffixed by `,ffc`) is supplied as an example.
This is a simple test program from RISC OS Pyromaniac which verifies the
behaviour of the SWI `OS_Write0`. It can be used to demonstrate the behaviour
of the tool:

```
charles@laputa ~/riscos-disassemble-python $ python -m riscos_disassemble hello_world,ffc
00000000 : e28f001c : .... : ADR     r0, &00000024
00000004 : ef000002 : .... : SWI     OS_Write0
00000008 : e28f1020 :  ... : ADR     r1, &00000030
0000000c : e1500001 : ..P. : CMP     r0, r1
00000010 : 1a000001 : .... : BNE     &0000001c
00000014 : ef000003 : .... : SWI     OS_NewLine
00000018 : e1a0f00e : .... : MOV     pc, lr
0000001c : e28f000c : .... : ADR     r0, &00000030
00000020 : ef00002b : +... : SWI     OS_GenerateError
00000024 : 6c6c6548 : Hell : STCLVS  p5, c6, [r12], #-&120
00000028 : 6f77206f : o wo : SWIVS   &77206f
0000002c : 00646c72 : rld. : RSBEQ   r6, r4, r2, ROR r12
00000030 : 00000001 : .... : ANDEQ   r0, r0, r1
00000034 : 6f203052 : R0 o : SWIVS   &203052
00000038 : 6572206e : n re : LDRBVS  r2, [r2, #-&6e]!
0000003c : 6e727574 : turn : MRCVS   p5, #3, r7, c2, c4, #3
00000040 : 6f726620 :  fro : SWIVS   &726620
00000044 : 534f206d : m OS : MOVTPL  r2, #&f06d                ; #61549
00000048 : 6972575f : _Wri : LDMDBVS r2!, {r0, r1, r2, r3, r4, r6, r8, r9, r10, r12, lr} ^
0000004c : 20306574 : te0  : EORSHS  r6, r0, r4, ROR r5
00000050 : 20736177 : was  : RSBSHS  r6, r3, r7, ROR r1
00000054 : 20746f6e : not  : RSBSHS  r6, r4, lr, ROR #30
00000058 : 72726f63 : corr : RSBSVC  r6, r2, #&18c
0000005c : 6c746365 : ectl : LDCLVS  p3, c6, [r4], #-&194
00000060 : 65732079 : y se : LDRBVS  r2, [r3, #-&79]!
00000064 : 6f742074 : t to : SWIVS   &742074
00000068 : 65687420 :  the : STRBVS  r7, [r8, #-&420]!
0000006c : 72657420 :  ter : RSBVC   r7, r5, #32, #8
00000070 : 616e696d : mina : Undefined instruction
00000074 : 00726f74 : tor. : RSBSEQ  r6, r2, r4, ROR pc
```

The bulk of the disassembly is textual data, but this is still decoded as if it is
executable.
