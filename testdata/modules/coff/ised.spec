# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto ISED compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	ised replace "PUSH r64" $REPLACEMENT +first
	entry "go"
	export
