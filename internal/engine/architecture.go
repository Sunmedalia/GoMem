package engine

// architectureMatches keeps 64-bit Intel and ARM tables distinct even though
// both use eight-byte pointers. Empty metadata retains legacy ISF support.
func architectureMatches(native, selected string) bool {
	switch native {
	case "":
		return true
	case "EM_X86_64", "x86_64", "x64":
		return selected == "x64"
	case "EM_386", "i386", "x86":
		return selected == "x86" || selected == "pae"
	case "EM_AARCH64", "aarch64", "arm64":
		return selected == "arm64"
	default:
		return false
	}
}
