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
	var download, localOnly, forceRemote bool
	cmd := &cobra.Command{Use: "match IMAGE", Short: "Match local symbols first, then remote URLs; optionally prompt to download", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := library.ProbeFile(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		l := library.Library{Root: *root}
		local, err := l.MatchLocal(cmd.Context(), p)
		if err != nil {
			return err
		}
		remote := library.Remote{Offline: c.Offline}
		matches := []library.Candidate{}
		remoteStatus := "not queried: matching local symbols available"
		var remoteErr error
		switch {
		case c.Offline:
			remoteStatus = "offline: local matching only"
		case localOnly:
			remoteStatus = "local matching only"
		case len(local.Matches) == 0 || forceRemote:
			matches, remoteErr = remote.Lookup(cmd.Context(), p)
			remoteStatus = "queried"
			if remoteErr != nil {
				remoteStatus = remoteErr.Error()
			}
		}
		if err = jsonOut(out, map[string]any{"probe": p, "local": local, "matches": matches, "remote_status": remoteStatus}); err != nil {
			return err
		}
		if remoteErr != nil {
			return remoteErr
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
	cmd.Flags().BoolVar(&localOnly, "local-only", false, "Match local tables only; do not contact the remote catalog")
	cmd.Flags().BoolVar(&forceRemote, "remote", false, "Also query remote URLs when local tables match")
	cmd.MarkFlagsMutuallyExclusive("local-only", "remote")
	cmd.Flags().BoolVar(&download, "download", false, "Ask before downloading each matching table into symbols/")
	return cmd
}
