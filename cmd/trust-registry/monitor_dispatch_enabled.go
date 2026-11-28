//go:build maintainer

package main

import "io"

const monitorUsage = " | monitor-list | monitor-fetch | monitor-local | monitor-diff | monitor-add | monitor-history | monitor-verify | monitor-plan | monitor-run"

func dispatchMonitor(args []string, out io.Writer) (bool, error) {
	switch args[0] {
	case "monitor-run":
		return true, runMonitorChecks(args[1:], out)
	case "monitor-add", "monitor-history", "monitor-verify", "monitor-plan":
		return true, runMonitorStore(args, out)
	case "monitor-list", "monitor-fetch", "monitor-local", "monitor-diff":
		return true, runSourceMonitor(args, out)
	default:
		return false, nil
	}
}
