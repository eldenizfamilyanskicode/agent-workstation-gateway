package artifactpattern

import "testing"

func TestMatchPortableArtifactPatterns(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		candidate string
		matched   bool
	}{
		{name: "exact", pattern: "report.json", candidate: "report.json", matched: true},
		{name: "segment star", pattern: "reports/*.json", candidate: "reports/result.json", matched: true},
		{name: "star does not cross slash", pattern: "reports/*.json", candidate: "reports/nested/result.json"},
		{name: "recursive one", pattern: "reports/**/*.json", candidate: "reports/nested/result.json", matched: true},
		{name: "recursive many", pattern: "reports/**/*.json", candidate: "reports/a/b/result.json", matched: true},
		{name: "recursive zero", pattern: "reports/**/result.json", candidate: "reports/result.json", matched: true},
		{name: "leading recursive", pattern: "**/*.png", candidate: "screenshots/page.png", matched: true},
		{name: "leading recursive root", pattern: "**/*.png", candidate: "page.png", matched: true},
		{name: "trailing recursive", pattern: "logs/**", candidate: "logs/a/b/output.txt", matched: true},
		{name: "question", pattern: "result-?.json", candidate: "result-1.json", matched: true},
		{name: "class", pattern: "result-[0-9].json", candidate: "result-7.json", matched: true},
		{name: "case sensitive", pattern: "Reports/*.json", candidate: "reports/result.json"},
		{name: "suffix mismatch", pattern: "**/*.json", candidate: "result.txt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matched, err := Match(test.pattern, test.candidate)
			if err != nil {
				t.Fatalf("match: %v", err)
			}
			if matched != test.matched {
				t.Fatalf("Match(%q, %q)=%t, want %t", test.pattern, test.candidate, matched, test.matched)
			}
		})
	}
}

func TestMatchRejectsMalformedSegmentGlob(t *testing.T) {
	if _, err := Match("reports/[.json", "reports/result.json"); err == nil {
		t.Fatal("expected malformed glob rejection")
	}
}

func TestCouldMatchDescendant(t *testing.T) {
	tests := []struct {
		pattern string
		prefix  string
		want    bool
	}{
		{pattern: "reports/**/*.json", prefix: "reports", want: true},
		{pattern: "reports/**/*.json", prefix: "reports/nested", want: true},
		{pattern: "reports/*.json", prefix: "screenshots"},
		{pattern: "**/*.txt", prefix: ".git", want: true},
		{pattern: "result.json", prefix: "result.json"},
		{pattern: "results/**", prefix: "results", want: true},
	}
	for _, test := range tests {
		actual, err := CouldMatchDescendant(test.pattern, test.prefix)
		if err != nil {
			t.Fatalf("CouldMatchDescendant(%q, %q): %v", test.pattern, test.prefix, err)
		}
		if actual != test.want {
			t.Fatalf("CouldMatchDescendant(%q, %q)=%t, want %t", test.pattern, test.prefix, actual, test.want)
		}
	}
}
