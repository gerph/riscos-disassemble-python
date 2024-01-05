# RISC OS disassembly in Python

## Introduction

This repository contains the module used to disassemble ARM and Thumb code
for RISC OS Pyromaniac. It uses the Capstone library to do so, but modifies
the output so that the disassembly is in a form which is generally seen by
RISC OS users.

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
