# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto unwind compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic
	linkpost "unwind_resource" "unwind"
	entry "go"
	export
