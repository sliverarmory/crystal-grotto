# SPDX-License-Identifier: GPL-3.0-only
# Original Crystal Grotto compatibility fixture.

x86:
  before "push": pack $HOOK_KEY "h" 0f
  after "push": xor $HOOK_KEY

x64:
  before "push": pack $HOOK_KEY "h" 0f
  after "push": xor $HOOK_KEY
