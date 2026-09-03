package sourceversion

import "testing"

func TestCanonicalGitSHA(t *testing.T) {
	valid := "0123456789abcdef0123456789abcdef01234567"
	if !IsCanonicalGitSHA(valid) {
		t.Fatal("canonical source SHA was rejected")
	}
	for _, invalid := range []string{
		"", valid[:39], valid + "0", "0123456789ABCDEF0123456789abcdef01234567",
		"g123456789abcdef0123456789abcdef01234567", "refs/heads/main", "0000000000000000000000000000000000000000\x00",
	} {
		if IsCanonicalGitSHA(invalid) {
			t.Fatalf("invalid source SHA was accepted: %q", invalid)
		}
	}
}
