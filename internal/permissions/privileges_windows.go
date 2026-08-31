//go:build windows

package permissions

func checkSystemRoot() bool {
	return false
}

func dropPrivileges(username string) error {
	return nil
}
