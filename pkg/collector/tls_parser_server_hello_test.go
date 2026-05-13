package collector

import (
	"encoding/hex"
	"testing"
)

func TestParseTLSServerHelloTLS13(t *testing.T) {
	// Golden ServerHello bytes shaped according to the FoxIO JA4S field order:
	// protocol/version/ext-count/ALPN, chosen cipher, ordered extension hash.
	raw := mustDecodeHex(t, "160303005b020000570303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f130100000f002b00020304001000050003026832")
	info := ParseTLSServerHello(raw)
	if info.Status != TLSParseStatusParsed || !info.HandshakeSeen {
		t.Fatalf("status=%s handshake=%t", info.Status, info.HandshakeSeen)
	}
	if info.TLSVersion != "1.3" || info.ALPN != "h2" {
		t.Fatalf("unexpected negotiated fields: %#v", info)
	}
	if info.JA4S != "t1302h2_1301_14e9539264dc" {
		t.Fatalf("JA4S = %s", info.JA4S)
	}
}

func TestParseTLSServerHelloTLS12(t *testing.T) {
	raw := mustDecodeHex(t, "1603030035020000310303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00c02f000009001000050003026832")
	info := ParseTLSServerHello(raw)
	if info.Status != TLSParseStatusParsed {
		t.Fatalf("status=%s", info.Status)
	}
	if info.TLSVersion != "1.2" || info.JA4S != "t1201h2_c02f_0b08e3dcc50f" {
		t.Fatalf("unexpected ServerHello info: %#v", info)
	}
}

func TestParseTLSServerHelloFragmentedAndNonServer(t *testing.T) {
	raw := mustDecodeHex(t, "160303005b020000570303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f130100000f002b00020304001000050003026832")
	if got := ParseTLSServerHello(raw[:20]); got.Status != TLSParseStatusFragmented {
		t.Fatalf("fragmented status = %s", got.Status)
	}
	clientHello := buildClientHelloForTest(clientHelloSpec{
		sni:               "example.com",
		alpn:              "h2",
		supportedVersions: []uint16{0x0304},
		ciphers:           []uint16{0x1301},
		extensions:        []uint16{0x0000, 0x0010, 0x002b},
	})
	if got := ParseTLSServerHello(clientHello); got.Status != TLSParseStatusNotServerHello {
		t.Fatalf("non-server status = %s", got.Status)
	}
}

func mustDecodeHex(t *testing.T, raw string) []byte {
	t.Helper()
	out, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}
