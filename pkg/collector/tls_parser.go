package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	TLSParseStatusParsed         = "parsed"
	TLSParseStatusFragmented     = "fragmented"
	TLSParseStatusNotClientHello = "not_clienthello"
	TLSParseStatusParseError     = "parse_error"
)

type TLSHandshakeInfo struct {
	HandshakeSeen bool
	TLSVersion    string
	SNIHash       string
	ALPN          string
	JA4           string
	Status        string
}

type clientHelloSpec struct {
	recordVersion      uint16
	clientVersion      uint16
	sni                string
	alpn               string
	supportedVersions  []uint16
	ciphers            []uint16
	extensions         []uint16
	signatureAlgos     []uint16
	signatureAlgosCert []uint16
}

func ParseTLSClientHello(data []byte) TLSHandshakeInfo {
	spec, status := parseClientHello(data)
	if status != TLSParseStatusParsed {
		return TLSHandshakeInfo{Status: status}
	}
	info := TLSHandshakeInfo{
		HandshakeSeen: true,
		TLSVersion:    tlsVersionString(spec.effectiveVersion()),
		ALPN:          spec.alpn,
		JA4:           spec.ja4(),
		Status:        TLSParseStatusParsed,
	}
	if spec.sni != "" {
		sum := sha256.Sum256([]byte(strings.ToLower(spec.sni)))
		info.SNIHash = hex.EncodeToString(sum[:])[:16]
	}
	return info
}

func parseClientHello(data []byte) (clientHelloSpec, string) {
	var spec clientHelloSpec
	if len(data) == 0 || data[0] != 0x16 {
		return spec, TLSParseStatusNotClientHello
	}
	if len(data) < 6 {
		return spec, TLSParseStatusFragmented
	}
	if data[5] != 0x01 {
		return spec, TLSParseStatusNotClientHello
	}
	if len(data) < 9 {
		return spec, TLSParseStatusFragmented
	}

	spec.recordVersion = be16(data[1:3])
	recordLen := int(be16(data[3:5]))
	if len(data) < 5+recordLen {
		return spec, TLSParseStatusFragmented
	}
	handshakeLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if len(data) < 9+handshakeLen {
		return spec, TLSParseStatusFragmented
	}

	body := data[9 : 9+handshakeLen]
	if len(body) < 35 {
		return spec, TLSParseStatusParseError
	}
	spec.clientVersion = be16(body[0:2])
	pos := 34

	sessionIDLen := int(body[pos])
	pos++
	if !has(body, pos, sessionIDLen) {
		return spec, TLSParseStatusParseError
	}
	pos += sessionIDLen

	if !has(body, pos, 2) {
		return spec, TLSParseStatusParseError
	}
	cipherLen := int(be16(body[pos : pos+2]))
	pos += 2
	if cipherLen%2 != 0 || !has(body, pos, cipherLen) {
		return spec, TLSParseStatusParseError
	}
	for i := 0; i < cipherLen; i += 2 {
		spec.ciphers = append(spec.ciphers, be16(body[pos+i:pos+i+2]))
	}
	pos += cipherLen

	if !has(body, pos, 1) {
		return spec, TLSParseStatusParseError
	}
	compressionLen := int(body[pos])
	pos++
	if !has(body, pos, compressionLen) {
		return spec, TLSParseStatusParseError
	}
	pos += compressionLen

	if pos == len(body) {
		return spec, TLSParseStatusParsed
	}
	if !has(body, pos, 2) {
		return spec, TLSParseStatusParseError
	}
	extensionsLen := int(be16(body[pos : pos+2]))
	pos += 2
	if !has(body, pos, extensionsLen) {
		return spec, TLSParseStatusParseError
	}
	end := pos + extensionsLen
	for pos < end {
		if !has(body, pos, 4) {
			return spec, TLSParseStatusParseError
		}
		extType := be16(body[pos : pos+2])
		extLen := int(be16(body[pos+2 : pos+4]))
		pos += 4
		if !has(body, pos, extLen) {
			return spec, TLSParseStatusParseError
		}
		extData := body[pos : pos+extLen]
		pos += extLen
		spec.extensions = append(spec.extensions, extType)
		switch extType {
		case 0x0000:
			spec.sni = parseSNI(extData)
		case 0x0010:
			spec.alpn = parseALPN(extData)
		case 0x002b:
			spec.supportedVersions = parseSupportedVersions(extData)
		case 0x000d:
			spec.signatureAlgos = parseUint16Vector(extData)
		case 0x0032:
			spec.signatureAlgosCert = parseUint16Vector(extData)
		}
	}
	if pos != end {
		return spec, TLSParseStatusParseError
	}
	return spec, TLSParseStatusParsed
}

func (s clientHelloSpec) effectiveVersion() uint16 {
	var best uint16
	for _, v := range s.supportedVersions {
		if isGREASE(v) {
			continue
		}
		if best == 0 || tlsVersionRank(v) > tlsVersionRank(best) {
			best = v
		}
	}
	if best != 0 {
		return best
	}
	if s.recordVersion != 0 {
		return s.recordVersion
	}
	return s.clientVersion
}

func (s clientHelloSpec) ja4() string {
	version := ja4TLSVersion(s.effectiveVersion())
	sniIndicator := "i"
	if s.sni != "" {
		sniIndicator = "d"
	}
	ciphers := nonGREASEHex(s.ciphers)
	extensionsForCount := nonGREASEHex(s.extensions)
	extensionsForHash := nonGREASEExtensionsForHash(s.extensions)
	signatureAlgos := nonGREASEHexPreserveOrder(s.signatureAlgos)
	if len(s.signatureAlgosCert) > 0 {
		signatureAlgos = nonGREASEHexPreserveOrder(s.signatureAlgosCert)
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		version,
		sniIndicator,
		cap99(len(ciphers)),
		cap99(len(extensionsForCount)),
		ja4ALPN(s.alpn),
		hashList(ciphers),
		hashExtensions(extensionsForHash, signatureAlgos),
	)
}

func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(be16(data[0:2]))
	pos := 2
	end := pos + listLen
	if end > len(data) {
		return ""
	}
	for pos < end {
		if !has(data, pos, 3) {
			return ""
		}
		nameType := data[pos]
		nameLen := int(be16(data[pos+1 : pos+3]))
		pos += 3
		if !has(data, pos, nameLen) {
			return ""
		}
		if nameType == 0 {
			return string(data[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func parseALPN(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(be16(data[0:2]))
	pos := 2
	if pos+listLen > len(data) || listLen == 0 {
		return ""
	}
	if !has(data, pos, 1) {
		return ""
	}
	valueLen := int(data[pos])
	pos++
	if valueLen == 0 || !has(data, pos, valueLen) {
		return ""
	}
	return string(data[pos : pos+valueLen])
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	if n%2 != 0 || !has(data, 1, n) {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, be16(data[1+i:1+i+2]))
	}
	return out
}

func parseUint16Vector(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	n := int(be16(data[0:2]))
	if n%2 != 0 || !has(data, 2, n) {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, be16(data[2+i:2+i+2]))
	}
	return out
}

func nonGREASEHex(values []uint16) []string {
	out := nonGREASEHexPreserveOrder(values)
	sort.Strings(out)
	return out
}

func nonGREASEHexPreserveOrder(values []uint16) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if isGREASE(v) {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	return out
}

func nonGREASEExtensionsForHash(values []uint16) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if isGREASE(v) || v == 0x0000 || v == 0x0010 {
			continue
		}
		out = append(out, fmt.Sprintf("%04x", v))
	}
	sort.Strings(out)
	return out
}

func hashList(values []string) string {
	if len(values) == 0 {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(strings.Join(values, ",")))
	return hex.EncodeToString(sum[:])[:12]
}

func hashExtensions(extensions, signatureAlgos []string) string {
	if len(extensions) == 0 {
		return "000000000000"
	}
	raw := strings.Join(extensions, ",")
	if len(signatureAlgos) > 0 {
		raw += "_" + strings.Join(signatureAlgos, ",")
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4ALPN(alpn string) string {
	if alpn == "" {
		return "00"
	}
	b := []byte(alpn)
	first := b[0]
	last := b[len(b)-1]
	if len(b) == 1 {
		last = first
	}
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		return string([]byte{first, last})
	}
	hexValue := hex.EncodeToString(b)
	return string([]byte{hexValue[0], hexValue[len(hexValue)-1]})
}

func ja4TLSVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func tlsVersionString(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	case 0x0300:
		return "ssl3"
	default:
		return "unknown"
	}
}

func tlsVersionRank(v uint16) int {
	switch v {
	case 0x0304:
		return 5
	case 0x0303:
		return 4
	case 0x0302:
		return 3
	case 0x0301:
		return 2
	case 0x0300:
		return 1
	default:
		return 0
	}
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func cap99(v int) int {
	if v > 99 {
		return 99
	}
	return v
}

func be16(data []byte) uint16 {
	return uint16(data[0])<<8 | uint16(data[1])
}

func has(data []byte, pos, n int) bool {
	return pos >= 0 && n >= 0 && pos <= len(data) && n <= len(data)-pos
}
