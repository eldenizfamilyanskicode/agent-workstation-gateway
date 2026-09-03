package main

import (
	"errors"
	"testing"
)

const commandTestSourceSHA = "0123456789abcdef0123456789abcdef01234567"

func TestBrokerCommandPassesOnlyFixedStartupInputs(t *testing.T) {
	called := false
	exitCode := run(
		[]string{"--installation-root", `C:\ProgramData\AgentWorkstationGateway`},
		commandTestSourceSHA,
		func(root string, sourceSHA string) error {
			called = true
			if root != `C:\ProgramData\AgentWorkstationGateway` || sourceSHA != commandTestSourceSHA {
				t.Fatal("broker command changed its fixed startup inputs")
			}
			return nil
		},
	)
	if exitCode != 0 || !called {
		t.Fatal("valid service command did not dispatch")
	}
}

func TestBrokerCommandRejectsAlternateModesAndArguments(t *testing.T) {
	tests := [][]string{
		nil,
		{"console"},
		{"--installation-root"},
		{"--installation-root", ""},
		{"--installation-root", `C:\ProgramData\AgentWorkstationGateway`, "request-selected"},
		{"--credential", `C:\ProgramData\AgentWorkstationGateway\state\execution-credential.dpapi`},
	}
	for _, args := range tests {
		called := false
		if exitCode := run(args, commandTestSourceSHA, func(string, string) error {
			called = true
			return nil
		}); exitCode != 1 || called {
			t.Fatalf("alternate broker arguments were dispatched: %#v", args)
		}
	}
}

func TestBrokerCommandMapsServiceFailureToClosedExit(t *testing.T) {
	exitCode := run(
		[]string{"--installation-root", `C:\ProgramData\AgentWorkstationGateway`},
		commandTestSourceSHA,
		func(string, string) error { return errors.New("synthetic service failure") },
	)
	if exitCode != 1 {
		t.Fatalf("service failure returned exit code %d", exitCode)
	}
	if exitCode := run(
		[]string{"--installation-root", `C:\ProgramData\AgentWorkstationGateway`},
		commandTestSourceSHA,
		nil,
	); exitCode != 1 {
		t.Fatal("missing service dependency did not fail closed")
	}
}
