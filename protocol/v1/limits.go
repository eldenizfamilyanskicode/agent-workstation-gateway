package v1

const (
	MaxRequestBytes       = 64 * 1024
	MaxScriptBytes        = 48 * 1024
	MaxIdentifierBytes    = 64
	MaxWorkingPathBytes   = 1024
	MinTimeoutSeconds     = 1
	MaxTimeoutSeconds     = 24 * 60 * 60
	MinOutputBytes        = 1024
	MaxOutputBytes        = 5 * 1024 * 1024
	MaxArtifactGroups     = 8
	MaxArtifactGroupBytes = 32
	MaxArtifactPaths      = 16
	MaxArtifactPathBytes  = 256
	MaxTotalArtifactPaths = 64
)
