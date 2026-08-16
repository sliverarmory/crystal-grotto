// SPDX-License-Identifier: GPL-3.0-only

package cli

import grotto "github.com/sliverarmory/crystal-grotto"

func noneForTest() (grotto.Capability, error) { return grotto.None("x64") }

func runOptionsForTest(environment map[string]any) grotto.RunOptions {
	return grotto.RunOptions{Environment: grotto.Environment(environment)}
}
