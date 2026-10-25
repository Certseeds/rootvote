package cli

import "github.com/Certseeds/rootvote/internal/exitcode"

const (
	ExitOK              = exitcode.OK
	ExitError           = exitcode.Error
	ExitUsage           = exitcode.Usage
	ExitPermission      = exitcode.Permission
	ExitAppRunning      = exitcode.AppRunning
	ExitManifestInvalid = exitcode.ManifestInvalid
	ExitPrimaryPassword = exitcode.PrimaryPassword
	ExitNSSMissing      = exitcode.NSSMissing
)
