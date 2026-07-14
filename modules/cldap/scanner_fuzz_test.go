package cldap

import (
	"testing"

	ber "gopkg.in/asn1-ber.v1"
)

// FuzzDecodeCldapResponse fuzzes ber.DecodePacket with arbitrary bytes and exercises
// the int64 type assertion used in Scan.
func FuzzDecodeCldapResponse(f *testing.F) {
	f.Add(CldapRecursionQuery())
	f.Fuzz(func(t *testing.T, data []byte) {
		packet := ber.DecodePacket(data)
		if packet != nil && len(packet.Children) > 0 {
			_, _ = packet.Children[0].Value.(int64)
		}
	})
}
