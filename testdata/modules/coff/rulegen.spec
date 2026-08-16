name "Crystal Grotto YARA compatibility module"
describe "Structural rule generation fixture"
author "Crystal Grotto contributors"
reference "https://github.com/sliverarmory/crystal-grotto"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	rule "compat" 1 1 "3-16" "go"
	entry "go"
	export
