//go:build !unix

package test

import (
	"errors"
	"os"
	"os/exec"
)

func setCmdProcessGroup(cmd *exec.Cmd) {
	// No-op on non-unix.
}

func signalCmdProcessGroup(cmd *exec.Cmd, sig os.Signal) error {
	if cmd.Process == nil {
		return errors.New("process not started")
	}
	if sig == nil {
		return cmd.Process.Kill()
	}
	return cmd.Process.Signal(sig)
}

