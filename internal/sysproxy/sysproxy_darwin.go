//go:build darwin

package sysproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

func listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var services []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// Enable sets the system SOCKS proxy on macOS via networksetup.
func Enable(host string, port int) error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	portStr := fmt.Sprintf("%d", port)
	for _, svc := range services {
		if err := exec.Command("networksetup", "-setsocksfirewallproxy", svc, host, portStr).Run(); err != nil {
			return fmt.Errorf("set socks proxy on %s: %w", svc, err)
		}
		if err := exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").Run(); err != nil {
			return fmt.Errorf("enable socks proxy on %s: %w", svc, err)
		}
	}
	return nil
}

// Disable restores macOS proxy settings to default (no SOCKS proxy).
func Disable() error {
	services, err := listNetworkServices()
	if err != nil {
		return err
	}
	for _, svc := range services {
		if err := exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run(); err != nil {
			return fmt.Errorf("disable socks proxy on %s: %w", svc, err)
		}
	}
	return nil
}
