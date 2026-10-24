package cli

import "github.com/Certseeds/rootvote/internal/exitcode"

const (
	ExitOK                     = exitcode.OK
	ExitError                  = exitcode.Error
	ExitUsage                  = exitcode.Usage
	ExitPermission             = exitcode.Permission
	ExitFirefoxRunning         = exitcode.FirefoxRunning
	ExitManifestInvalid        = exitcode.ManifestInvalid
	ExitFirefoxPrimaryPassword = exitcode.FirefoxPrimaryPassword
	ExitNSSMissing             = exitcode.NSSMissing
)
