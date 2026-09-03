package sourceversion

// IsCanonicalGitSHA accepts the v0.1 source identity format used by protocol
// reports and trusted release linker metadata.
func IsCanonicalGitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
