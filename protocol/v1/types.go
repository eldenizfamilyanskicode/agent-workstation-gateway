package v1

type ProtocolVersion uint8

const Version ProtocolVersion = 1

type Shell string

type RequestOperation string

const (
	ShellBash       Shell = "bash"
	ShellCmd        Shell = "cmd"
	ShellGitBash    Shell = "git-bash"
	ShellPowerShell Shell = "powershell"
	ShellPwsh       Shell = "pwsh"
)

const (
	RequestOperationExecute RequestOperation = "execute"
	RequestOperationStart   RequestOperation = "start"
	RequestOperationStatus  RequestOperation = "status"
	RequestOperationStop    RequestOperation = "stop"
	RequestOperationLogs    RequestOperation = "logs"
)

type Request struct {
	ProtocolVersion  ProtocolVersion     `json:"protocol_version"`
	RequestID        string              `json:"request_id"`
	SessionID        string              `json:"session_id"`
	Actor            string              `json:"actor"`
	Operation        RequestOperation    `json:"operation"`
	ProcessID        string              `json:"process_id"`
	Shell            Shell               `json:"shell"`
	WorkingDirectory string              `json:"working_directory"`
	Script           string              `json:"script"`
	TimeoutSeconds   int                 `json:"timeout_seconds"`
	MaxOutputBytes   int                 `json:"max_output_bytes"`
	Artifacts        []ArtifactSelection `json:"artifacts"`
}

type ArtifactSelection struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
}
