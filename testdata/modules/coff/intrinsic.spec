# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto user intrinsic compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	intrinsic "__custom" $REPLACEMENT
	entry "go"
	export
