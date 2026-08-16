# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto transfer intrinsic compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	entry "go"
	export
