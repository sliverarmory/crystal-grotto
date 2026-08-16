# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto hook resolver compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	addhook "KERNEL32$Sleep" "wrapper"
	entry "go"
	export
