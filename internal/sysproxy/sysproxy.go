// Package sysproxy configures system-wide proxy settings to route all
// OS traffic through the local SOCKS5 proxy.
// Supports Windows (registry), macOS (networksetup), and Linux (gsettings/env).
//
// The Enable and Disable functions are implemented per platform via build tags.
package sysproxy
