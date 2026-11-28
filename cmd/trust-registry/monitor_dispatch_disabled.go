//go:build !maintainer

package main

import (
	"errors"
	"io"
	"strings"
)

const monitorUsage = ""

func dispatchMonitor(args []string, out io.Writer) (bool, error) {
	if strings.HasPrefix(args[0], "monitor-") {
		return true, errors.New("source monitoring is available only in the source-built maintainer CLI")
	}
	return false, nil
}
