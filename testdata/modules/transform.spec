# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto compatibility fixture.

x86:
  pack $KEY "h" 0f0e
  pack $DATA "h" 0011223344
  push $DATA
  xor $KEY
  preplen

x64:
  pack $KEY "h" 0f0e
  pack $DATA "h" 0011223344
  push $DATA
  xor $KEY
  preplen
