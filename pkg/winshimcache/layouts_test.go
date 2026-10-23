package winshimcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestShimcacheEmbeddedLayouts(t *testing.T) {
	names := LayoutNames()
	if len(names) != 12 {
		t.Fatalf("embedded layout count = %d", len(names))
	}
	for _, name := range names {
		embedded, err := LayoutData(name)
		if err != nil {
			t.Fatal(err)
		}
		upstream, err := os.ReadFile(filepath.Join(
			"..", "..", ".cache",
			"volatility3-881e970121c16f0932fb9d16fbd5fb258cbcbf75",
			"volatility3", "framework", "symbols", "windows", "shimcache",
			name+".json",
		))
		if err != nil {
			if os.IsNotExist(err) {
				t.Logf("pinned source absent; embedded %s digest %s", name, sha256.Sum256(embedded))
				continue
			}
			t.Fatal(err)
		}
		if string(embedded) != string(upstream) {
			t.Fatalf("%s differs from pinned source", name)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(embedded, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, name := range []string{"", "../layout", "missing"} {
		if _, err := LayoutData(name); err == nil {
			t.Fatalf("accepted invalid layout name %q", name)
		}
	}
}

func TestShimcacheEmbeddedLayoutDigests(t *testing.T) {
	want := map[string]string{
		"shimcache-2003-x64":   "adbb60490f8cc75d454e7a294ab2718cdafdb46331e9ced1add54e3e9c8e328a",
		"shimcache-2003-x86":   "d0866e9fdec58d9c8d7cd0b59414e448c8352f843ea9da328775c9a084750680",
		"shimcache-vista-x64":  "b1521af0b06705c23ffbbc47112cd1e4d728787d0280a034cf932d3ef939b9ee",
		"shimcache-vista-x86":  "8af230402ef0701d3b6680c01f18243dc58017a29224ff2e4630c88b9906924e",
		"shimcache-win10-x64":  "d24bd939fa47c12da21ba1ddcf212208a180d3f9aab489ee074abdb3c74ce6bc",
		"shimcache-win10-x86":  "637b210ba8912a143f9489e341f479d42ea9ebdbcb8f456ba2f13a4e4ccbbd5c",
		"shimcache-win7-x64":   "c5419ce783c2779f33117a37ef33f69a67d79ae8e812d1281303b3540645c4ed",
		"shimcache-win7-x86":   "84b4b060f29873293429d02aebfe3eaff47c1c31a14170d7221149eb567737d0",
		"shimcache-win8-x64":   "42433dfdaff4cb7963e9166c6952d5bd0feed89ead9a0e6020367540d7315fad",
		"shimcache-win8-x86":   "ce4312ab5bb1dc53e70ab5d9d243ef2d77f216c9a9d42a8772ab3118c95e7834",
		"shimcache-xp-sp2-x86": "155b807ac6b188ca3b2055d5d61eba0771fe31547c03d14856e6123dfe24ea05",
		"shimcache-xp-sp3-x86": "68e7ef06e0eab1a625a66be2b7696b157acc7ebcce6134dd4953e3a5af92652d",
	}
	for name, digest := range want {
		raw, err := LayoutData(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != digest {
			t.Errorf("%s digest = %s, want %s", name, got, digest)
		}
	}
}
