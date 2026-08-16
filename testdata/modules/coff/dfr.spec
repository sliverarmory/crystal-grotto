name "Crystal Grotto DFR compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	dfr "resolve" "ror13"
	entry "go"
	export
