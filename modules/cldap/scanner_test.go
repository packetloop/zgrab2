package cldap

import (
	"testing"

	ber "gopkg.in/asn1-ber.v1"
)

// TestCldapRecursionQuery verifies the probe parses as valid BER and carries the expected transaction ID.
func TestCldapRecursionQuery(t *testing.T) {
	probe := CldapRecursionQuery()
	if len(probe) == 0 {
		t.Fatal("probe is empty")
	}
	packet := ber.DecodePacket(probe)
	if packet == nil {
		t.Fatal("failed to decode probe as BER")
	}
	if len(packet.Children) == 0 {
		t.Fatal("decoded packet has no children")
	}
	id, ok := packet.Children[0].Value.(int64)
	if !ok {
		t.Fatalf("first child value is not int64, got %T", packet.Children[0].Value)
	}
	if id != transaction_id {
		t.Errorf("transaction ID mismatch: got %d, want %d", id, transaction_id)
	}
}
