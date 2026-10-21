package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/library"
	"github.com/spf13/cobra"
)

func imageCommands(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "images", Short: "Inspect memory image OS and resident kernel identities"}
	cmd.AddCommand(&cobra.Command{Use: "inspect PATH", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := library.ProbeFile(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return jsonOut(out, p)
	}})
	return cmd
}

func matchSymbols(c *engine.Config, root *string, out io.Writer) *cobra.Command {
	var download bool
	cmd := &cobra.Command{Use: "match IMAGE", Short: "Match resident kernel identities to exact symbol URLs; optionally prompt to download", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := library.ProbeFile(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		remote := library.Remote{Offline: c.Offline}
		matches, err := remote.Lookup(cmd.Context(), p)
		if err != nil {
			return err
		}
		if err = jsonOut(out, map[string]any{"probe": p, "matches": matches}); err != nil {
			return err
		}
		if !download {
			return nil
		}
		scanner := bufio.NewScanner(cmd.InOrStdin())
		for _, match := range matches {
			fmt.Fprintf(out, "Download %s? [y/N] ", match.URL)
			if !scanner.Scan() {
				return scanner.Err()
			}
			answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if answer != "y" && answer != "yes" {
				continue
			}
			path, err := remote.Download(cmd.Context(), library.Library{Root: *root}, match)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, path)
		}
		return nil
	}}
	cmd.Flags().BoolVar(&download, "download", false, "Ask before downloading each matching table into sysmbols/")
	return cmd
}
