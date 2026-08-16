name "Crystal Grotto fixbss compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	fixbss "getbss"
	entry "go"
	export
