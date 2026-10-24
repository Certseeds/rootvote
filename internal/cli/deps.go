package cli

import (
	"context"
	"os"

	"github.com/charmbracelet/huh"

	"github.com/Certseeds/rootvote/internal/apply"
	"github.com/Certseeds/rootvote/internal/buildinfo"
	"github.com/Certseeds/rootvote/internal/ccadb"
)

type Deps struct {
	Version   string
	Snapshot  string
	LoadData  func() ([]ccadb.Record, string, error)
	ApplyFunc func(context.Context, apply.Options, apply.Deps) (apply.Result, error)
	UndoFunc  func(context.Context, apply.UndoOptions, apply.Deps) (apply.Result, error)
	IsTTY     func() bool
	Confirm   func(string) bool
}

func DefaultDeps() Deps {
	return Deps{
		Version:   buildinfo.Version,
		Snapshot:  buildinfo.CCADBSnapshot,
		LoadData:  ccadb.Load,
		ApplyFunc: apply.Run,
		UndoFunc:  apply.RunUndo,
		IsTTY:     isTTY,
		Confirm:   confirmHuh,
	}
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func confirmHuh(prompt string) bool {
	var ok bool
	err := huh.NewConfirm().Title(prompt).Value(&ok).Run()
	return err == nil && ok
}
