//go:build windows

package protectedstate

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestExactProtectedStateDescriptors(t *testing.T) {
	tests := []struct {
		name      string
		sddl      string
		directory bool
		rule      string
	}{
		{name: "file", sddl: FileSDDL},
		{name: "directory", sddl: DirectorySDDL, directory: true},
		{name: "extra reader", sddl: "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)", rule: "credential-acl-not-exact"},
		{name: "file inherits", sddl: "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", rule: "credential-ace-permissions-invalid"},
		{name: "directory does not inherit", sddl: FileSDDL, directory: true, rule: "credential-ace-permissions-invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal("could not create synthetic protected-state descriptor")
			}
			if test.directory {
				err = ValidateExactDirectoryDescriptor(descriptor)
			} else {
				err = ValidateExactFileDescriptor(descriptor)
			}
			if test.rule == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var failure *Error
			if !errors.As(err, &failure) || failure.Rule != test.rule {
				t.Fatalf("expected %s, got %T / %v", test.rule, err, err)
			}
		})
	}
}
