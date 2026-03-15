//go:build linux

package sysproxy

import (
	"fmt"
	"os/exec"
)

// Enable sets the system SOCKS proxy on Linux via gsettings/kwriteconfig5.
func Enable(host string, port int) error {
	proxyURL := fmt.Sprintf("socks5://%s:%d", host, port)

	if path, err := exec.LookPath("gsettings"); err == nil && path != "" {
		cmds := [][]string{
			{"gsettings", "set", "org.gnome.system.proxy", "mode", "manual"},
			{"gsettings", "set", "org.gnome.system.proxy.socks", "host", host},
			{"gsettings", "set", "org.gnome.system.proxy.socks", "port", fmt.Sprintf("%d", port)},
		}
		for _, args := range cmds {
			if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
				return fmt.Errorf("gsettings: %w", err)
			}
		}
	}

	if path, err := exec.LookPath("kwriteconfig5"); err == nil && path != "" {
		cmds := [][]string{
			{"kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1"},
			{"kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", proxyURL},
		}
		for _, args := range cmds {
			if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
				return fmt.Errorf("kwriteconfig5: %w", err)
			}
		}
	}

	return nil
}

// Disable restores Linux proxy settings to default (no proxy).
func Disable() error {
	if path, err := exec.LookPath("gsettings"); err == nil && path != "" {
		if err := exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run(); err != nil {
			return fmt.Errorf("gsettings: %w", err)
		}
	}

	if path, err := exec.LookPath("kwriteconfig5"); err == nil && path != "" {
		if err := exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0").Run(); err != nil {
			return fmt.Errorf("kwriteconfig5: %w", err)
		}
	}

	return nil
}
