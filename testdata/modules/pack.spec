# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto compatibility fixture.

x86:
  pack $RESULT "bsilpazZhx" 0x7f 0x1234 0x89abcdef 0x0102030405060708 0x11223344 "Hi" "A" "B" deadbeef
  push $RESULT

x64:
  pack $RESULT "bsilpazZhx" 0x7f 0x1234 0x89abcdef 0x0102030405060708 0x11223344 "Hi" "A" "B" deadbeef
  push $RESULT
