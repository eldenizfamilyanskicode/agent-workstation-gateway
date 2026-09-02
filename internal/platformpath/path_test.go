package platformpath

import "testing"

func TestValidateAbsoluteAcceptsCanonicalPaths(t *testing.T) {
	values := []struct {
		platform Platform
		value    string
	}{
		{platform: Windows, value: `C:\Users\Alice\Projects`},
		{platform: Windows, value: `D:\Tools\Git\bin\bash.exe`},
		{platform: Linux, value: "/home/alice/projects"},
		{platform: Linux, value: "/usr/bin/bash"},
	}
	for _, test := range values {
		if err := ValidateAbsolute(test.platform, test.value); err != nil {
			t.Fatalf("valid %s path rejected: %v", test.platform, err)
		}
	}
}

func TestValidateAbsoluteRejectsAliasesAndUnsafeForms(t *testing.T) {
	values := []struct {
		platform Platform
		value    string
	}{
		{platform: Windows, value: `c:\Users\Alice`},
		{platform: Windows, value: `C:\Users\Alice\..\Admin`},
		{platform: Windows, value: `C:\Users\Alice\\Projects`},
		{platform: Windows, value: `C:\Users\Alice\NUL.txt`},
		{platform: Windows, value: `\\server\share`},
		{platform: Linux, value: "home/alice"},
		{platform: Linux, value: "/home/alice/../root"},
		{platform: Linux, value: "/home//alice"},
		{platform: Linux, value: `/home/alice\projects`},
	}
	for _, test := range values {
		if err := ValidateAbsolute(test.platform, test.value); err == nil {
			t.Fatalf("unsafe path accepted for %s", test.platform)
		}
	}
}

func TestContainsUsesSegmentAndPlatformCaseRules(t *testing.T) {
	if !Contains(Windows, `C:\Users\Alice\Projects`, `c:\users\alice\projects\demo`) {
		t.Fatal("Windows descendant was not recognized case-insensitively")
	}
	if Contains(Windows, `C:\Users\Alice\Projects`, `C:\Users\Alice\Projects-Other`) {
		t.Fatal("Windows sibling prefix was treated as a descendant")
	}
	if !Contains(Linux, "/home/alice/projects", "/home/alice/projects/demo") {
		t.Fatal("Linux descendant was not recognized")
	}
	if Contains(Linux, "/home/alice/projects", "/home/Alice/projects/demo") {
		t.Fatal("Linux path comparison ignored case")
	}
}

func TestRootAndOverlap(t *testing.T) {
	if !IsFilesystemRoot(Windows, `C:\`) || !IsFilesystemRoot(Linux, "/") {
		t.Fatal("filesystem root was not recognized")
	}
	if !Overlaps(Linux, "/srv/projects", "/srv/projects/demo") {
		t.Fatal("nested roots were not recognized as overlapping")
	}
	if Overlaps(Linux, "/srv/project-a", "/srv/project-b") {
		t.Fatal("disjoint roots were treated as overlapping")
	}
}
