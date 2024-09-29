##
# Makefile for RISCOS Disassembler
#
# Remove stale .pyc files:
#	- `make clean`
#
# Build a package:
#	- `make package`
#     Ensure that project.config is updated.
#
# Run simple tests
#	- `make tests`
#

VERSION = $(shell eval "$$(tools/ci-vars)" ; echo $$CI_BRANCH_VERSION)

clean:
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

package: tmp-setup.py
	python tmp-setup.py sdist

tmp-setup.py: project.config setup.py
	sed 's/version = ".*"/version = "${VERSION}"/' setup.py > tmp-setup.py || ( rm tmp-setup.py ; false )

tests: tests-plain tests-colour tests-plus tests-map tests-match tests-simple


tests-plain:
	mkdir -p test-output/plain
	for i in examples/* ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking plain: $$name" ; python -m riscos_disassemble $$i > test-output/plain/$$name ; cmp test-output/plain/$$name test-expect/plain/$$name ; done

tests-colour:
	mkdir -p test-output/colour
	for i in examples/* ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking colour: $$name" ; python -m riscos_disassemble --colour $$i > test-output/colour/$$name ; cmp test-output/colour/$$name test-expect/colour/$$name ; done

tests-plus:
	mkdir -p test-output/plus
	for i in examples/SystemBell,ffa ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking plus(lower): $$name" ; python -m riscos_disassemble --debuggerplus=-lower $$i > test-output/plus/$$name ; cmp test-output/plus/$$name test-expect/plus/$$name ; done

tests-map:
	mkdir -p test-output/functionmap
	for i in examples/kerneldebug,ffc ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking functionmap: $$name" ; python -m riscos_disassemble --function-map $$i > test-output/functionmap/$$name ; cmp test-output/functionmap/$$name test-expect/functionmap/$$name ; done

tests-match:
	mkdir -p test-output/match
	for i in examples/aarch64_hello_world,ff8 ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking match: $$name" ; python -m riscos_disassemble --match clock $$i > test-output/match/$$name ; cmp test-output/match/$$name test-expect/match/$$name ; done

tests-simple:
	mkdir -p test-output/simple
	for i in examples/hello_world,ffc ; do name=$$(basename "$$i" | sed 's/,...$$//') ; echo "Checking simple: $$name" ; python simple_disassemble.py $$i > test-output/simple/$$name ; cmp test-output/simple/$$name test-expect/simple/$$name ; done
