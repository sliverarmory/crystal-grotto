# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto compatibility fixture.

emit.x86:
  pack $RESULT "vz" $PREFIX %1
  push $RESULT

emit.x64:
  pack $RESULT "vz" $PREFIX %1
  push $RESULT
