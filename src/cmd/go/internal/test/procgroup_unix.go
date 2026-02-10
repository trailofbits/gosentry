//go:build unix

package test

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func setCmdProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func signalCmdProcessGroup(cmd *exec.Cmd, sig os.Signal) error {
	if cmd.Process == nil {
		return errors.New("process not started")
	}
	pid := cmd.Process.Pid

	if sig == nil {
		// Kill the process group to avoid leaking children (e.g. `cargo run` -> runner).
		return syscall.Kill(-pid, syscall.SIGKILL)
	}

	if s, ok := sig.(syscall.Signal); ok {
		// Negative pid sends to the process group.
		return syscall.Kill(-pid, s)
	}

	// Fallback (should not happen on unix).
	return cmd.Process.Signal(sig)
}

