//go:build !windows

package permissions

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"
)

func checkSystemRoot() bool {
	return syscall.Getuid() == 0
}

func dropPrivileges(username string) error {
	if !checkSystemRoot() {
		return nil // Already non-root
	}

	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("user not found: %s", username)
	}

	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}

	return nil
}
