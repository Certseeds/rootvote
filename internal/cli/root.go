package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

type app struct {
	stdout io.Writer
	stderr io.Writer
	deps   Deps
}

func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithDeps(args, stdout, stderr, DefaultDeps())
}

func RunWithDeps(args []string, stdout, stderr io.Writer, deps Deps) int {
	a := &app{stdout: stdout, stderr: stderr, deps: deps}
	root := a.newRootCmd()
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	if err := root.Execute(); err != nil {
		var ce *cmdError
		if errors.As(err, &ce) {
			if ce.err != nil {
				fmt.Fprintln(stderr, ce.err)
			}
			return ce.code
		}
		if strings.Contains(err.Error(), "unknown command") {
			fmt.Fprintln(stderr, "未知命令")
			return ExitUsage
		}
		fmt.Fprintln(stderr, err)
		return ExitError
	}
	return ExitOK
}

type cmdError struct {
	code int
	err  error
}

func (e *cmdError) Error() string {
	if e.err == nil {
		return fmt.Sprint("exit code ", e.code)
	}
	return e.err.Error()
}

func (e *cmdError) Unwrap() error { return e.err }

func codeError(code int, err error) error { return &cmdError{code: code, err: err} }

func (a *app) newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "rootvote",
		Short:         "按国家/地区拉黑 CA 根证书",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = cmd.Help()
			return codeError(ExitUsage, nil)
		},
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return codeError(ExitUsage, err)
	})
	root.AddCommand(
		a.newVersionCmd(),
		a.newCountriesCmd(),
		a.newGenerateCmd(),
		a.newDisplayCmd(),
		a.newStatusCmd(),
		a.newDoctorCmd(),
	)
	return root
}

func (a *app) newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "显示版本",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(a.stdout, "rootvote", a.deps.Version)
			fmt.Fprintln(a.stdout, "ccadb", a.deps.Snapshot)
			return nil
		},
	}
}
