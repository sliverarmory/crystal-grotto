# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto upstream-compatibility fixture.

name "Crystal Grotto ordering disco compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x86.o:
	push $OBJECT
	make pic +disco
	entry "_go"
	export

x64.o:
	push $OBJECT
	make pic +disco
	entry "go"
	export
