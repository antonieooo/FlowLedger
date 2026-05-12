package collector

import (
	"encoding/hex"
	"testing"
)

func TestParseTLSClientHelloFoxIOReferenceVector(t *testing.T) {
	hello := buildClientHelloForTest(clientHelloSpec{
		sni:               "example.com",
		alpn:              "h2",
		supportedVersions: []uint16{0x0304, 0x0303},
		ciphers:           []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		extensions:        []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		signatureAlgos:    []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	})
	info := ParseTLSClientHello(hello)
	if info.Status != TLSParseStatusParsed || !info.HandshakeSeen {
		t.Fatalf("status=%s handshake=%t", info.Status, info.HandshakeSeen)
	}
	if info.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Fatalf("JA4 = %s", info.JA4)
	}
	if info.TLSVersion != "1.3" || info.ALPN != "h2" || info.SNIHash == "" {
		t.Fatalf("unexpected TLS info: %#v", info)
	}
	if info.SNIHash != "a379a6f6eeafb9a5" {
		t.Fatalf("SNIHash = %s", info.SNIHash)
	}
}

func TestParseTLSClientHelloCurlLikeVector(t *testing.T) {
	hello := buildClientHelloForTest(clientHelloSpec{
		sni:               "example.com",
		alpn:              "http/1.1",
		supportedVersions: []uint16{0x0304, 0x0303},
		ciphers:           []uint16{0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0x009e, 0x009f, 0x006b, 0x0067, 0x0039, 0x003c, 0x0033, 0x0035, 0x002f, 0x00ff},
		extensions:        []uint16{0x0000, 0x000b, 0x000a, 0x0010, 0x0016, 0x0017, 0x000d, 0x002b, 0x0033},
		signatureAlgos:    []uint16{0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601},
	})
	info := ParseTLSClientHello(hello)
	if info.Status != TLSParseStatusParsed {
		t.Fatalf("status=%s", info.Status)
	}
	if info.JA4 != "t13d1709h1_6aad9e4a5b8f_47d270fe2fe6" {
		t.Fatalf("JA4 = %s", info.JA4)
	}
}

func TestParseTLSClientHelloGoLikeVector(t *testing.T) {
	hello := buildClientHelloForTest(clientHelloSpec{
		sni:               "example.com",
		alpn:              "h2",
		supportedVersions: []uint16{0x0304, 0x0303},
		ciphers:           []uint16{0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		extensions:        []uint16{0x0000, 0x000b, 0xff01, 0x0017, 0x0012, 0x0005, 0x000a, 0x000d, 0x002b, 0x0033, 0x0010},
		signatureAlgos:    []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	})
	info := ParseTLSClientHello(hello)
	if info.Status != TLSParseStatusParsed {
		t.Fatalf("status=%s", info.Status)
	}
	if info.JA4 != "t13d1411h2_c866b44c5a26_f2c32ca98d96" {
		t.Fatalf("JA4 = %s", info.JA4)
	}
}

func TestParseTLSClientHelloFragmentedAndNonTLS(t *testing.T) {
	hello := buildClientHelloForTest(clientHelloSpec{
		sni:               "example.com",
		alpn:              "h2",
		supportedVersions: []uint16{0x0304},
		ciphers:           []uint16{0x1301},
		extensions:        []uint16{0x0000, 0x0010, 0x002b},
	})
	if got := ParseTLSClientHello(hello[:50]); got.Status != TLSParseStatusFragmented {
		t.Fatalf("truncated status = %s", got.Status)
	}
	if got := ParseTLSClientHello([]byte("GET / HTTP/1.1\r\n\r\n")); got.Status != TLSParseStatusNotClientHello {
		t.Fatalf("non-TLS status = %s", got.Status)
	}
}

func buildClientHelloForTest(spec clientHelloSpec) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)

	ciphers := []byte{}
	for _, cipher := range spec.ciphers {
		ciphers = appendUint16(ciphers, cipher)
	}
	body = appendUint16(body, uint16(len(ciphers)))
	body = append(body, ciphers...)
	body = append(body, 1, 0)

	extensions := []byte{}
	for _, ext := range spec.extensions {
		extensions = appendExtensionForTest(extensions, ext, spec)
	}
	body = appendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01}
	record = appendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record
}

func appendExtensionForTest(out []byte, ext uint16, spec clientHelloSpec) []byte {
	data := []byte{}
	switch ext {
	case 0x0000:
		name := []byte(spec.sni)
		serverName := []byte{0}
		serverName = appendUint16(serverName, uint16(len(name)))
		serverName = append(serverName, name...)
		data = appendUint16(data, uint16(len(serverName)))
		data = append(data, serverName...)
	case 0x0010:
		proto := []byte(spec.alpn)
		list := []byte{byte(len(proto))}
		list = append(list, proto...)
		data = appendUint16(data, uint16(len(list)))
		data = append(data, list...)
	case 0x002b:
		versions := []byte{}
		for _, version := range spec.supportedVersions {
			versions = appendUint16(versions, version)
		}
		data = append(data, byte(len(versions)))
		data = append(data, versions...)
	case 0x000d:
		algos := []byte{}
		for _, algo := range spec.signatureAlgos {
			algos = appendUint16(algos, algo)
		}
		data = appendUint16(data, uint16(len(algos)))
		data = append(data, algos...)
	default:
		if ext == 0x0033 {
			data, _ = hex.DecodeString("0029001d00200000000000000000000000000000000000000000000000000000000000000000")
		}
	}
	out = appendUint16(out, ext)
	out = appendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func appendUint16(out []byte, v uint16) []byte {
	return append(out, byte(v>>8), byte(v))
}
