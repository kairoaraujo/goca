package utils

import (
	"net"
)

// Parse []string to []net.IP
func ParseStrings2IPs(ipStrings []string) []net.IP {
	result := []net.IP{}

	for _, str := range ipStrings {
		ip := net.ParseIP(str)
		if ip == nil {
			continue
		}

		result = append(result, ip)
	}

	return result
}

// Parse []net.IP to []string
func ParseIPs2Strings(ips []net.IP) []string {
	result := []string{}

	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result
}
