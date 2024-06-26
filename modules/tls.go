package modules

import (
	log "github.com/sirupsen/logrus"
	"github.com/packetloop/zgrab2"
)

type TLSFlags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
}

type TLSModule struct {
}

type TLSScanner struct {
	config *TLSFlags
}

type TLSCerts struct {
	Raw   []byte   `json:"raw"`
	Chain [][]byte `json:"chain"`
}

func init() {
	var tlsModule TLSModule
	_, err := zgrab2.AddCommand("tls", "TLS Banner Grab", "Grab banner over TLS", 443, &tlsModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *TLSModule) NewFlags() interface{} {
	return new(TLSFlags)
}

func (m *TLSModule) NewScanner() zgrab2.Scanner {
	return new(TLSScanner)
}

func (f *TLSFlags) Validate(args []string) error {
	return nil
}

func (f *TLSFlags) Help() string {
	return ""
}

func (s *TLSScanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*TLSFlags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}
	s.config = f
	return nil
}

func (s *TLSScanner) GetName() string {
	return s.config.Name
}

func (s *TLSScanner) GetTrigger() string {
	return s.config.Trigger
}

func (s *TLSScanner) InitPerSender(senderID int) error {
	return nil
}

// Scan opens a TCP connection to the target (default port 443), then performs
// a TLS handshake. If the handshake gets past the ServerHello stage, the
// handshake log is returned (along with any other TLS-related logs, such as
// heartbleed, if enabled).
func (s *TLSScanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	conn, err := t.OpenTLS(&s.config.BaseFlags, &s.config.TLSFlags)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		if conn != nil {
			if log := conn.GetLog(); log != nil {
				if log.HandshakeLog.ServerHello != nil {
					// If we got far enough to get a valid ServerHello, then
					// consider it to be a positive TLS detection.
					return zgrab2.TryGetScanStatus(err), nil, err
				}
				// Otherwise, detection failed.
			}
		}
		return zgrab2.TryGetScanStatus(err), nil, err
	}

	certs := TLSCerts{}
	certs.Raw = conn.GetLog().HandshakeLog.ServerCertificates.Certificate.Raw
	certs.Chain = make([][]byte, len(conn.GetLog().HandshakeLog.ServerCertificates.Chain))
	for i := range conn.GetLog().HandshakeLog.ServerCertificates.Chain {
		certs.Chain[i] = conn.GetLog().HandshakeLog.ServerCertificates.Chain[i].Raw
	}
	return zgrab2.SCAN_SUCCESS, certs, nil
}

// Protocol returns the protocol identifer for the scanner.
func (s *TLSScanner) Protocol() string {
	return "tls"
}
