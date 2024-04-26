package utils

import (
	"log"
	"testing"
)

func TestParseIP(t *testing.T) {
	ips := ParseStrings2IPs([]string{
		"192.168.2.1",
		"192.168.2.2",
	})

	log.Println(ips)

	log.Println(ParseIPs2Strings(ips))
}
