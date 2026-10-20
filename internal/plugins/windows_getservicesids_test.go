package plugins

import "testing"

func TestServiceSIDHashAndKnownNames(t *testing.T) {
	if serviceSID("MyCustomSvc") != "S-1-5-80-1815667792-113514744-3657382036-3872625243-3339418493" {
		t.Fatal(serviceSID("MyCustomSvc"))
	}
	if serviceSID("bits") != "S-1-5-80-864916184-135290571-3087830041-1716922880-4237303741" {
		t.Fatal(serviceSID("bits"))
	}
	if serviceSID("É") != "S-1-5-80-1995128432-106489220-750934610-3208978093-3392209618" {
		t.Fatal(serviceSID("É"))
	}
	if serviceSID("") != "S-1-5-80-4003674586-223046494-4022293810-2417516693-151509167" {
		t.Fatal(serviceSID(""))
	}
	if serviceSID("AarSvc_73fe2") != "S-1-5-80-2016190367-80351949-2619848870-3635284754-1757174072" {
		t.Fatal(serviceSID("AarSvc_73fe2"))
	}
	if _, ok := windowsServiceNames["BITS"]; !ok {
		t.Fatal("BITS missing from pinned service names")
	}
	if _, ok := windowsServiceNames["AarSvc_73fe2"]; ok {
		t.Fatal("per-user service was treated as pinned")
	}
}
