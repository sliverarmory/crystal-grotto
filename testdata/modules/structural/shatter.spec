# SPDX-License-Identifier: GPL-3.0-only

name "Crystal Grotto shatter structural compatibility module"
author "Crystal Grotto contributors"
license "GPL-3.0-only"

x64.o:
	push $OBJECT
	make pic +shatter
	entry "go"
	export
