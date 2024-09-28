##
# Makefile for RISCOS Disassembler
#
# Remove stale .pyc files:
#	- `make clean`
#


clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete
