package cli

import "github.com/Certseeds/rootvote/internal/buildinfo"

type Deps struct {
	Version  string
	Snapshot string
}

func DefaultDeps() Deps {
	return Deps{Version: buildinfo.Version, Snapshot: buildinfo.CCADBSnapshot}
}
