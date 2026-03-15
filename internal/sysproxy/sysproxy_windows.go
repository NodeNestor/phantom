//go:build windows

package sysproxy

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const regPath = `Software\Microsoft\Windows\Internet Settings`

// Enable sets the system SOCKS proxy on Windows via the registry.
func Enable(host string, port int) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry: %w", err)
	}
	defer k.Close()

	proxyAddr := fmt.Sprintf("socks=%s:%d", host, port)
	if err := k.SetStringValue("ProxyServer", proxyAddr); err != nil {
		return fmt.Errorf("set ProxyServer: %w", err)
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}
	if err := k.SetStringValue("ProxyOverride", "<local>"); err != nil {
		return fmt.Errorf("set ProxyOverride: %w", err)
	}
	return nil
}

// Disable restores Windows proxy settings to default (no proxy).
func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, regPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		return fmt.Errorf("disable proxy: %w", err)
	}
	return nil
}
