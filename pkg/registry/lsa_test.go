package registry

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"strings"
	"testing"
)

func TestLSAVectorsMatchPinnedBaseline(t *testing.T) {
	boot := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	blob := mustHex(t, "454b4c53454b4c53454b4c53454b4c53454b4c53454b4c53454b4c53202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadf3fd8ca3d5501610a6e809548bd4bbb0cebbe1c2bad724e5cc070c85e78e95551cfb6f54f45cb481068a3476b7b6449e")
	plain, err := decryptAESLSA(blob, boot)
	if err != nil || hex.EncodeToString(plain[68:100]) != "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" {
		t.Fatal(hex.EncodeToString(plain), err)
	}
	lsa := plain[68:100]
	secret := mustHex(t, "53454352534543525345435253454352534543525345435253454352808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fc75ae2f456efd7dd78c22d6b3a5cbde6386562e2c5607329b4b67201634cfbb9")
	got, err := decryptAESLSA(secret, lsa)
	want := append(utf16Bytes("MachinePassword"), 0, 0)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal(hex.EncodeToString(got), err)
	}
	if _, err = decryptAESLSA(bytes.Repeat([]byte{0}, 61), boot); err == nil || !strings.Contains(err.Error(), "ciphertext is 1") {
		t.Fatal(err)
	}

	obf := mustHex(t, "3333333333333333333333337d167b6217210a309d43a3ef50dc77da2a73b54114b996c830abec6e6d3e6b8696bb83601958055b9110296646819c8c909192939495969798999a9b9c9d9e9f")
	sumPlain, err := rc4PreVista(obf, boot)
	if err != nil || hex.EncodeToString(sumPlain) != "101112131415161718191a1b1c1d1e1f" {
		t.Fatal(hex.EncodeToString(sumPlain), err)
	}
	enc := mustHex(t, "8bf719ba41bf86fdd85cbfbef8a0f5772fd8564d028a4e1a495de434f74546f3")
	desPlain, err := decryptSecret(enc, sumPlain)
	if err != nil || string(desPlain) != "DefaultPassword-XYZ" {
		t.Fatal(string(desPlain), err)
	}

	nlkm := mustHex(t, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	entry := mustHex(t, "0a000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000b0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000000000000000000000000000000dd08438b62d92d4b23479361e82e6347661c2f6cf96dde9a168ebb1f11b1ed858ae8edca02402c8c76836683544a5abbe414c60ac74a7b38771e5655b5ed122fdc00df11a8eadbd9f643174f6a928435ed46e3c284dbdc0d1f7c815f16394874779e95880b06f1a0ac2b04451803960f9d52fdab01d7e33463b9e7b065bb352e")
	parsed, skip, err := parseCacheEntry(entry)
	if err != nil || skip {
		t.Fatal(skip, err)
	}
	dec, err := decryptCachedHash(parsed.enc, nlkm, parsed.iv, false)
	if err != nil {
		t.Fatal(err)
	}
	user, domain, dns, hash := parseDecryptedCache(dec, parsed.userLen, parsed.domainLen, parsed.dnsLen)
	if user != "alice" || domain != "CORP" || dns != "corp.example" || hex.EncodeToString(hash) != "00112233445566778899aabbccddeeff" {
		t.Fatal(user, domain, dns, hex.EncodeToString(hash))
	}
	xpNLKM := append(mustHex(t, "101112131415161718191a1b1c1d1e1f"), []byte("xp-nlkm-pad")...)
	xp := mustHex(t, "0a000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecf00000000000000000000000000000000533cd63e28ff5bdc9ddb8118f11900e1808dd61cf2fd35442d62b08fae980a78e2733ed233a0341c524f11369f8fbaf28e7aa8b108ff6e56e1926cc4d20a76b39c5b51ef13555a4fc5bb5e176db5ace58253f8e6fcf001b30bea22b18cca80ba69420b738a3d64aa181e06376b6b1799a7898f6007c98c4e25870191f8eb008b")
	parsed, skip, err = parseCacheEntry(xp)
	if err != nil || skip {
		t.Fatal(skip, err)
	}
	dec, err = decryptCachedHash(parsed.enc, xpNLKM, parsed.iv, true)
	if err != nil {
		t.Fatal(err)
	}
	user, domain, dns, hash = parseDecryptedCache(dec, parsed.userLen, parsed.domainLen, parsed.dnsLen)
	if user != "alice" || domain != "CORP" || dns != "corp.example" || hex.EncodeToString(hash) != "00112233445566778899aabbccddeeff" {
		t.Fatal(user, domain, dns, hex.EncodeToString(hash))
	}
	if utf16Replace([]byte{'A', 0, 0xff}) != "A\uFFFD" {
		t.Fatal(utf16Replace([]byte{'A', 0, 0xff}))
	}
}

func TestDumpLSAAndCacheFromHives(t *testing.T) {
	k := newRAM("kernel")
	off := testOffsets()
	system := openBootHive(t, k, off)

	sec := mountTestHive(k, 0xffff800000010000, 0xffff800000011000, 0xffff800000012000, 0xffff800000013000, 0xffff800000200000)
	nlkmCurr := sec.addKey("CurrVal", nil, []hiveValue{{"Data", mustHex(t, "4e4c4b4d4e4c4b4d4e4c4b4d4e4c4b4d4e4c4b4d4e4c4b4d4e4c4b4d303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4fa15d7d65ca2d25aaba74c8678d84a966c0f0a857a9f749137516aec823ef54aa")}})
	secretCurr := sec.addKey("CurrVal", nil, []hiveValue{{"Data", mustHex(t, "53454352534543525345435253454352534543525345435253454352808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fc75ae2f456efd7dd78c22d6b3a5cbde6386562e2c5607329b4b67201634cfbb9")}})
	secrets := sec.addKey("Secrets", nil, nil, sec.addKey("NL$KM", nil, nil, nlkmCurr), sec.addKey("Secret", nil, nil, secretCurr), sec.addKey("Missing", nil, nil))
	policy := sec.addKey("Policy", nil, nil, sec.addKey("PolEKList", nil, []hiveValue{{"", mustHex(t, "454b4c53454b4c53454b4c53454b4c53454b4c53454b4c53454b4c53202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadd3ebc6118e9262503a860de98e254fadf3fd8ca3d5501610a6e809548bd4bbb0cebbe1c2bad724e5cc070c85e78e95551cfb6f54f45cb481068a3476b7b6449e")}}), secrets)
	empty := make([]byte, 96)
	cache := sec.addKey("Cache", nil, []hiveValue{
		{"NL$Control", []byte{1, 2, 3, 4}},
		{"NL$2", empty},
		{"NL$1", mustHex(t, "0a000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000b0b1b2b3b4b5b6b7b8b9babbbcbdbebf00000000000000000000000000000000dd08438b62d92d4b23479361e82e6347661c2f6cf96dde9a168ebb1f11b1ed858ae8edca02402c8c76836683544a5abbe414c60ac74a7b38771e5655b5ed122fdc00df11a8eadbd9f643174f6a928435ed46e3c284dbdc0d1f7c815f16394874779e95880b06f1a0ac2b04451803960f9d52fdab01d7e33463b9e7b065bb352e")},
	})
	sec.finish(sec.addKey("ROOT", nil, nil, policy, cache))
	security, err := Open(context.Background(), k, nil, 0xffff800000010000, "SECURITY", off)
	if err != nil {
		t.Fatal(err)
	}
	secretsOut, err := DumpLSA(context.Background(), system, security, true)
	if err == nil || len(secretsOut) != 3 || !strings.Contains(err.Error(), "Missing") {
		t.Fatal(len(secretsOut), err)
	}
	if secretsOut[0].Name != "NL$KM" || hex.EncodeToString(secretsOut[0].Data) != "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" || secretsOut[0].Err != nil {
		t.Fatal(secretsOut[0], hex.EncodeToString(secretsOut[0].Data))
	}
	if secretsOut[1].Name != "Secret" || !bytes.Equal(secretsOut[1].Data, append(utf16Bytes("MachinePassword"), 0, 0)) {
		t.Fatal(hex.EncodeToString(secretsOut[1].Data), secretsOut[1].Err)
	}
	if secretsOut[2].Err == nil {
		t.Fatal(secretsOut[2])
	}
	cacheOut, err := DumpCache(context.Background(), system, security, true)
	if err != nil || len(cacheOut) != 1 || cacheOut[0].Username != "alice" || cacheOut[0].Domain != "CORP" || cacheOut[0].DomainName != "corp.example" || hex.EncodeToString(cacheOut[0].Hash) != "00112233445566778899aabbccddeeff" || cacheOut[0].Value != "NL$1" {
		t.Fatal(cacheOut, err)
	}
	if _, err = DumpLSA(context.Background(), system, nil, true); err == nil || !strings.Contains(err.Error(), "SECURITY") {
		t.Fatal(err)
	}

	old := mountTestHive(k, 0xffff800000030000, 0xffff800000031000, 0xffff800000032000, 0xffff800000033000, 0xffff800000300000)
	oldCurr := old.addKey("CurrVal", nil, []hiveValue{{"Data", mustHex(t, "4444444444444444444444448bf719ba41bf86fdd85cbfbef8a0f5772fd8564d028a4e1a495de434f74546f3")}})
	oldNL := old.addKey("CurrVal", nil, []hiveValue{{"Data", mustHex(t, "444444444444444444444444381322f786cae16befcf44db284b176a8a73243386f2840bba2bb039614ef480861039655985f73c")}})
	oldSecrets := old.addKey("Secrets", nil, nil, old.addKey("DefaultPassword", nil, nil, oldCurr), old.addKey("NL$KM", nil, nil, oldNL))
	oldPolicy := old.addKey("Policy", nil, nil, old.addKey("PolSecretEncryptionKey", nil, []hiveValue{{"", mustHex(t, "3333333333333333333333337d167b6217210a309d43a3ef50dc77da2a73b54114b996c830abec6e6d3e6b8696bb83601958055b9110296646819c8c909192939495969798999a9b9c9d9e9f")}}), oldSecrets)
	oldCache := old.addKey("Cache", nil, []hiveValue{{"NL$1", mustHex(t, "0a000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecf00000000000000000000000000000000533cd63e28ff5bdc9ddb8118f11900e1808dd61cf2fd35442d62b08fae980a78e2733ed233a0341c524f11369f8fbaf28e7aa8b108ff6e56e1926cc4d20a76b39c5b51ef13555a4fc5bb5e176db5ace58253f8e6fcf001b30bea22b18cca80ba69420b738a3d64aa181e06376b6b1799a7898f6007c98c4e25870191f8eb008b")}})
	old.finish(old.addKey("ROOT", nil, nil, oldPolicy, oldCache))
	oldHive, err := Open(context.Background(), k, nil, 0xffff800000030000, "SECURITY", off)
	if err != nil {
		t.Fatal(err)
	}
	oldSecretsOut, err := DumpLSA(context.Background(), system, oldHive, false)
	if err != nil || len(oldSecretsOut) != 2 || oldSecretsOut[0].Name != "DefaultPassword" || string(oldSecretsOut[0].Data) != "DefaultPassword-XYZ" {
		t.Fatal(oldSecretsOut, err)
	}
	oldCacheOut, err := DumpCache(context.Background(), system, oldHive, false)
	if err != nil || len(oldCacheOut) != 1 || oldCacheOut[0].Username != "alice" || hex.EncodeToString(oldCacheOut[0].Hash) != "00112233445566778899aabbccddeeff" {
		t.Fatal(oldCacheOut, err)
	}
}

func openBootHive(t *testing.T, k *ram, off Offsets) *Hive {
	t.Helper()
	sys := mountTestHive(k, 0xffff800000001000, 0xffff800000002000, 0xffff800000003000, 0xffff800000004000, 0xffff800000100000)
	lsa := sys.addKey("Lsa", nil, nil,
		sys.addKey("JD", utf16Bytes("080a0307"), nil),
		sys.addKey("Skew1", utf16Bytes("0201090f"), nil),
		sys.addKey("GBG", utf16Bytes("00050d04"), nil),
		sys.addKey("Data", utf16Bytes("0b060c0e"), nil))
	sys.finish(sys.addKey("ROOT", nil, nil, sys.addKey("ControlSet001", nil, nil, sys.addKey("Control", nil, nil, lsa))))
	system, err := Open(context.Background(), k, nil, 0xffff800000001000, "SYSTEM", off)
	if err != nil {
		t.Fatal(err)
	}
	return system
}

func rc4PreVista(obf, boot []byte) ([]byte, error) {
	if len(obf) < 76 {
		return nil, errShortBlob
	}
	sum := md5.New()
	sum.Write(boot)
	salt := obf[60:76]
	for i := 0; i < 1000; i++ {
		sum.Write(salt)
	}
	plain, err := rc4Apply(sum.Sum(nil), obf[12:60])
	if err != nil || len(plain) < 0x20 {
		if err == nil {
			err = errShortBlob
		}
		return nil, err
	}
	return plain[0x10:0x20], nil
}

var errShortBlob = errString("short")

type errString string

func (e errString) Error() string { return string(e) }
