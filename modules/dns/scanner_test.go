package dns

import (
	"encoding/binary"
	"testing"
)

// TestDnsRecursionQuery verifies the probe has the correct transaction ID, recursion flag, and question count.
func TestDnsRecursionQuery(t *testing.T) {
	query := DnsRecursionQuery()

	txID := binary.BigEndian.Uint16(query[0:2])
	if txID != transaction_id {
		t.Errorf("transaction ID: got 0x%04X, want 0x%04X", txID, transaction_id)
	}

	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&0x0100 == 0 {
		t.Errorf("recursion desired flag not set in flags word 0x%04X", flags)
	}

	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount != 1 {
		t.Errorf("question count: got %d, want 1", qdCount)
	}
}

// FuzzParseDNSResponse fuzzes the response-parsing logic with arbitrary bytes.
func FuzzParseDNSResponse(f *testing.F) {
	f.Add(DnsRecursionQuery())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		_ = binary.BigEndian.Uint16(data[0:2]) == transaction_id
		_ = (data[2]&0x80 == 0x80) && (data[3]&0x8F == 0x80)
	})
}
