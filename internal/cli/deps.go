package cli

import (
	"github.com/Certseeds/rootvote/internal/buildinfo"
	"github.com/Certseeds/rootvote/internal/ccadb"
)

type Deps struct {
	Version  string
	Snapshot string
	LoadData func() ([]ccadb.Record, string, error)
}

func DefaultDeps() Deps {
	return Deps{
		Version:  buildinfo.Version,
		Snapshot: buildinfo.CCADBSnapshot,
		LoadData: ccadb.Load,
	}
}
