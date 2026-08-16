# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto mutate and register-dance compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic +mutate +regdance
	entry "go"
	export
