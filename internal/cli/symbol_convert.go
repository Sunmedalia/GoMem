package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
	"github.com/spf13/cobra"
)

func convertSymbols(c *engine.Config, out io.Writer) *cobra.Command {
	var options symbols.DWARFOptions
	var output string
	cmd := &cobra.Command{Use: "convert DEBUG_FILE", Short: "Convert ELF/Mach-O DWARF to ISF with native Go", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		options.OS = c.OS
		table, report, err := symbols.ConvertDWARF(cmd.Context(), args[0], options)
		if err != nil {
			return err
		}
		data, err := table.Encode()
		if err != nil {
			return err
		}
		target := output
		if target == "" && c.CaseDir != "" {
			dir := filepath.Join(c.CaseDir, "symbols")
			if err = os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			target = filepath.Join(dir, table.Digest()+".json")
		}
		if target == "" || target == "-" {
			if err = writeCanceled(cmd.Context(), out, data); err != nil {
				return err
			}
		} else {
			if err = writeNewSymbols(cmd.Context(), target, data); err != nil {
				return err
			}
			if _, err = fmt.Fprintln(out, target); err != nil {
				return err
			}
		}
		reportJSON, err := json.Marshal(report)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.ErrOrStderr(), string(reportJSON))
		return err
	}}
	flags := cmd.Flags()
	flags.StringVar(&output, "output", "", "New ISF path, '-' for stdout; default stdout or CASE/symbols/SHA256.json")
	flags.StringVar(&options.SystemMap, "system-map", "", "Optional Linux System.map; overrides ELF symbol addresses")
	flags.StringVar(&options.SymbolsFrom, "symbols-from", "", "Matching separate ELF/Mach-O file for symbol addresses and banner data")
	flags.StringVar(&options.Arch, "binary-arch", "", "Mach-O architecture: x86_64, i386, arm64, arm")
	flags.Uint64Var(&options.MaxDebugBytes, "max-debug-bytes", 512<<20, "Maximum aggregate debug-section bytes (at most 2 GiB)")
	flags.IntVar(&options.MaxEntries, "max-entries", 2000000, "Maximum DWARF entries and input symbols")
	return cmd
}
func writeCanceled(ctx context.Context, w io.Writer, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), 64<<10)
		written, err := w.Write(data[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func writeNewSymbols(ctx context.Context, path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			os.Remove(path)
		}
	}()
	if err = writeCanceled(ctx, f, data); err != nil {
		return err
	}
	return f.Sync()
}
