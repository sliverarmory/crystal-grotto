name "Crystal Grotto basic COFF compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x86.o:
	push $OBJECT
	make pic
	entry "_go"
	export

x64.o:
	push $OBJECT
	make pic
	entry "go"
	export
