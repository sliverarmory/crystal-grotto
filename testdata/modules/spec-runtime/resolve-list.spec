# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto compatibility fixture.

x86:
  set "%FILES" "canonical/../canonical/first.marker, canonical/./second.marker, "
  resolve "%FILES"
  pack $RESULT "z" %FILES
  push $RESULT

x64:
  set "%FILES" "canonical/../canonical/first.marker, canonical/./second.marker, "
  resolve "%FILES"
  pack $RESULT "z" %FILES
  push $RESULT
