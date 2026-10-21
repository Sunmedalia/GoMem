package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/Sunmedalia/GoMem/docs"
	"github.com/Sunmedalia/GoMem/internal/acceptance"
	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/explore"
	"github.com/Sunmedalia/GoMem/internal/plugins"
	"github.com/Sunmedalia/GoMem/internal/render"
	"github.com/Sunmedalia/GoMem/internal/report"
	"github.com/Sunmedalia/GoMem/internal/store"
	"github.com/Sunmedalia/GoMem/internal/triage"
	"github.com/Sunmedalia/GoMem/internal/tui"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
	"github.com/Sunmedalia/GoMem/pkg/symbols"
)

func New(in io.Reader, out, stderr io.Writer) *cobra.Command {
	var cfg engine.Config
	var format string
	root := &cobra.Command{Use: "gomem", Short: "Native Go memory forensics — development preview", Long: "GoMem is a native, read-only memory investigation engine. This development preview has incomplete Volatility 3 coverage; inspect capabilities and doctor before relying on a workflow.", Version: version.Version + " (Volatility " + version.Baseline + ", " + version.BaselineCommit + ")", SilenceErrors: true, SilenceUsage: true}
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(stderr)
	f := root.PersistentFlags()
	f.StringVar(&cfg.Image, "image", "", "Read-only memory image")
	f.StringVar(&cfg.CaseDir, "case", "", "Case directory (SQLite, symbols, exports)")
	f.StringVar(&cfg.Symbols, "symbols", "", "Matching ISF, PDB/MSF 7.0 or ELF/Mach-O with DWARF")
	f.StringVar(&cfg.SymbolIndex, "symbol-index", "", "Local symbol index; otherwise use CASE/symbols/index.json when DTB is given")
	f.StringVar(&cfg.SymbolCache, "symbol-cache", "", "Symbol cache (default CASE/symbols/windows, otherwise OS user cache)")
	f.StringVar(&cfg.SymbolServer, "symbol-server", symbols.MicrosoftSymbolServer, "HTTPS PDB symbol server base URL")
	f.StringVar(&cfg.OS, "os", "", "Target OS: windows, linux, mac")
	f.StringVar(&cfg.Arch, "arch", "auto", "Address translation: auto (crash metadata, otherwise x64), x64, x86, pae")
	f.StringVar(&cfg.DTB, "dtb", "", "Physical page-table root; optional for Windows crash dumps and supported Linux x64 kernels")
	f.Uint64Var(&cfg.KernelBase, "kernel-base", 0, "Windows kernel virtual base")
	f.Uint64Var(&cfg.KernelSlide, "kernel-slide", 0, "Linux virtual relocation added to symbol addresses")
	f.BoolVar(&cfg.Offline, "offline", false, "Disable symbol download; allow verified local cache reuse")
	f.StringVar(&format, "format", "table", "Output: table, jsonl, json, csv; export: html, jsonl, bundle")
	registry := plugin.NewRegistry()
	if err := plugins.Register(registry); err != nil {
		panic(err)
	}
	var params []string
	var fresh bool
	analyze := &cobra.Command{Use: "analyze PLUGIN", Short: "Stream a native plugin and persist evidence", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if target, ok := engine.DeprecatedPluginAliases[name]; ok {
			name = target
			fmt.Fprintf(stderr, "deprecated plugin %s delegates to %s\n", args[0], target)
		}
		p, err := registry.Get(name)
		if err != nil {
			return err
		}
		parsed, err := parameters(params)
		if err != nil {
			return err
		}
		if _, err = plugin.Parameters(p.Spec(), parsed); err != nil {
			return err
		}
		eng, err := engine.Open(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer eng.Close()
		if err = eng.Check(cmd.Context(), p.Spec()); err != nil {
			return err
		}
		writer, err := render.New(out, format, p.Spec().Columns)
		if err != nil {
			return err
		}
		res, runErr := eng.Run(cmd.Context(), args[0], parsed, engine.RunOptions{Fresh: fresh, Emit: writer.Row})
		closeErr := writer.Close()
		if res.Task.ID != "" {
			fmt.Fprintf(stderr, "task=%s state=%s rows=%d cached=%t\n", res.Task.ID, res.Task.State, res.Task.Rows, res.Reused)
		}
		return errors.Join(runErr, closeErr)
	}}
	analyze.Flags().StringArrayVarP(&params, "param", "p", nil, "Plugin parameter key=value; repeatable")
	analyze.Flags().BoolVar(&fresh, "fresh", false, "Run again instead of replaying a completed task")
	root.AddCommand(analyze)
	root.AddCommand(&cobra.Command{Use: "plugins [NAME]", Short: "List implemented plugins or inspect a parameter schema", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 {
			name := args[0]
			if target, ok := engine.DeprecatedPluginAliases[name]; ok {
				name = target
			}
			p, err := registry.Get(name)
			if err != nil {
				return err
			}
			spec := p.Spec()
			if name != args[0] {
				spec.Name = args[0]
				spec.Description = "Deprecated upstream name; delegates to " + name + ". " + spec.Description
			}
			return jsonOut(out, spec)
		}
		if format == "json" || format == "jsonl" {
			return jsonOut(out, registry.List())
		}
		for _, s := range registry.List() {
			if _, err := fmt.Fprintf(out, "%-22s %s\n", s.Name, s.Description); err != nil {
				return err
			}
		}
		return nil
	}})
	root.AddCommand(&cobra.Command{Use: "capabilities", Short: "Show the complete locked upstream acceptance inventory", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error { _, err := out.Write(docs.Capabilities); return err }})
	var strict bool
	doctor := &cobra.Command{Use: "doctor", Short: "Inspect build capabilities, prerequisites and the release gate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var matrix struct {
			PluginCount int `json:"plugin_count"`
			Accepted    int `json:"accepted_plugins"`
		}
		if err := json.Unmarshal(docs.Capabilities, &matrix); err != nil {
			return err
		}
		gate, err := acceptance.Inspect()
		if err != nil {
			return err
		}
		build, err := version.Identity()
		if err != nil {
			return err
		}
		diagnostic := map[string]any{"engine": version.Version, "release": "development-preview", "baseline": version.Baseline, "baseline_commit": version.BaselineCommit, "native_plugins": registry.List(), "upstream_plugin_classes": matrix.PluginCount, "accepted_plugins": matrix.Accepted, "release_ready": false, "extensions": map[string]bool{"yara": false, "capstone": false, "leechcore": false}, "formats": []string{"raw", "lime-v1", "avml-v2-snappy-framed", "elf-core-physical-pt_load", "windows-complete-32/64", "windows-bitmap-32/64"}, "symbol_inputs": []string{"isf-json/gzip/xz/zip", "elf-dwarf", "macho-dwarf", "pdb-msf7-codeview"}, "missing": []string{"complete image/kernel/DTB discovery (partial Linux x64 and Windows crash only)", "Linux/macOS automatic symbol acquisition and CAB PDB transport", "full PDB/CodeView and legacy MSF validation", "full DWARF/kernel-version validation", "macOS analysis", "swap resolution", "VMware/QEMU/Xen and full format/version acceptance", "remote sources", "full plugin parameter parity", "official-corpus differential acceptance", "full renderers and extraction"}}
		diagnostic["release_ready"] = gate.Ready
		diagnostic["symbol_lookup"] = "explicit table, local identity index or exact Windows PDB acquisition (known DTB/kernel base required)"
		diagnostic["acceptance"] = gate
		diagnostic["build_sha256"] = build
		if cfg.Image != "" {
			eng, err := engine.Open(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			diagnostic["image_sha256"] = eng.Hash
			diagnostic["image_format"] = eng.Format
			diagnostic["selected_os"] = eng.Env.OS
			diagnostic["dtb"] = eng.Config.DTB
			diagnostic["selected_arch"] = eng.Config.Arch
			diagnostic["kernel_base"] = fmt.Sprintf("0x%x", eng.Config.KernelBase)
			if eng.CrashHeader != nil {
				diagnostic["crash_header_hints"] = eng.CrashHeader
			}
			if eng.WindowsDiscovery != nil {
				diagnostic["windows_discovery"] = eng.WindowsDiscovery
			}
			if eng.WindowsDiscoveryError != nil {
				diagnostic["windows_discovery_error"] = eng.WindowsDiscoveryError.Error()
			}
			if eng.Discovery != nil {
				diagnostic["discovery"] = eng.Discovery
			}
			if eng.SymbolResolution != nil {
				diagnostic["symbol_resolution"] = eng.SymbolResolution
			}
			if eng.Env.Symbols != nil {
				diagnostic["symbols_sha256"] = eng.Env.Symbols.Digest()
				diagnostic["symbols_location"] = eng.Config.Symbols
			}
			eng.Close()
		}
		if err := jsonOut(out, diagnostic); err != nil {
			return err
		}
		if strict && !gate.Ready {
			return fmt.Errorf("release gate closed: %d/%d official plugins accepted", matrix.Accepted, matrix.PluginCount)
		}
		return nil
	}}
	doctor.Flags().BoolVar(&strict, "strict", false, "Fail when formal release acceptance is incomplete")
	root.AddCommand(doctor)
	root.AddCommand(&cobra.Command{Use: "tui", Short: "Open the asynchronous, paginated investigation TUI; without --image it starts in the image importer", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		var eng *engine.Engine
		if cfg.Image != "" {
			var err error
			if eng, err = engine.Open(cmd.Context(), cfg); err != nil {
				return err
			}
			defer eng.Close()
		}
		ctx, cancel := context.WithCancel(cmd.Context())
		program := tea.NewProgram(tui.New(ctx, tui.Options{Config: cfg, Engine: eng}), tea.WithInput(in), tea.WithOutput(out), tea.WithContext(ctx))
		final, err := program.Run()
		cancel()
		program.Wait()
		// The TUI may have switched images; close whichever engine it holds.
		return errors.Join(err, tui.Close(final))
	}})
	root.AddCommand(&cobra.Command{Use: "shell", Short: "Explore memory, types and address spaces interactively", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		eng, err := engine.Open(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer eng.Close()
		s := explore.New(eng)
		fmt.Fprintln(stderr, "GoMem development shell. Use help; quit exits. Addresses accept 0x hexadecimal.")
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "quit" || line == "exit" {
				return nil
			}
			if cmd.Context().Err() != nil {
				return cmd.Context().Err()
			}
			if err = s.Execute(cmd.Context(), line, out); err != nil {
				fmt.Fprintln(stderr, "error:", err)
			}
		}
		return scanner.Err()
	}})
	var needles []string
	triageCmd := &cobra.Command{Use: "triage", Short: "Run available checks and explicitly report coverage gaps (nonzero if incomplete)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if cfg.CaseDir == "" {
			return fmt.Errorf("triage requires --case to retain findings")
		}
		eng, err := engine.Open(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		defer eng.Close()
		summary, runErr := triage.Run(cmd.Context(), eng, needles)
		return errors.Join(runErr, jsonOut(out, summary))
	}}
	triageCmd.Flags().StringArrayVar(&needles, "ioc", nil, "Exact literal to scan, repeatable")
	root.AddCommand(triageCmd)
	var output, task string
	exportCmd := &cobra.Command{Use: "export", Short: "Write HTML, JSONL or a verified evidence bundle inside the case", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if cfg.CaseDir == "" {
			return fmt.Errorf("export requires --case")
		}
		st, err := store.Open(cfg.CaseDir)
		if err != nil {
			return err
		}
		defer st.Close()
		kind := format
		if kind == "table" {
			kind = "html"
		}
		name := output
		if name == "" {
			ext := kind
			if kind == "bundle" {
				ext = "zip"
			}
			name = "investigation." + ext
		}
		path, err := report.Export(cmd.Context(), st, kind, name, task)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, path)
		return err
	}}
	exportCmd.Flags().StringVar(&output, "output", "", "New filename inside CASE/exports (never overwrites)")
	exportCmd.Flags().StringVar(&task, "task", "", "Export one task ID; default all tasks")
	root.AddCommand(exportCmd)
	root.AddCommand(symbolCommands(&cfg, out))
	root.AddCommand(caseCommands(&cfg, out))
	return root
}
func jsonOut(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func parameters(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range values {
		k, val, ok := strings.Cut(v, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("parameter must be key=value")
		}
		if _, ok := out[k]; ok {
			return nil, fmt.Errorf("duplicate parameter %q", k)
		}
		out[k] = val
	}
	return out, nil
}
func caseCommands(c *engine.Config, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "case", Short: "Inspect tasks and maintain investigation notes"}
	open := func() (*store.Store, error) {
		if c.CaseDir == "" {
			return nil, fmt.Errorf("--case is required")
		}
		info, err := os.Stat(filepath.Join(c.CaseDir, "case.db"))
		if err != nil {
			return nil, fmt.Errorf("open existing case: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("case database is not a regular file")
		}
		return store.Open(c.CaseDir)
	}
	cmd.AddCommand(&cobra.Command{Use: "tasks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := open()
		if err != nil {
			return err
		}
		defer s.Close()
		tasks, err := s.Tasks(cmd.Context())
		if err != nil {
			return err
		}
		return jsonOut(out, tasks)
	}})
	var artifactTask string
	var artifactOffset, artifactLimit int
	artifacts := &cobra.Command{Use: "artifacts", Short: "List one page of extracted-file metadata", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := open()
		if err != nil {
			return err
		}
		defer s.Close()
		page, err := s.ArtifactPage(cmd.Context(), artifactTask, artifactOffset, artifactLimit)
		if err != nil {
			return err
		}
		return jsonOut(out, page)
	}}
	artifacts.Flags().StringVar(&artifactTask, "task", "", "Owner task ID; otherwise all tasks")
	artifacts.Flags().IntVar(&artifactOffset, "offset", 0, "Artifact page offset")
	artifacts.Flags().IntVar(&artifactLimit, "limit", 100, "Page size (1..1000)")
	cmd.AddCommand(artifacts)
	var verifyTask string
	verify := &cobra.Command{Use: "verify-artifacts", Short: "Verify all extraction files and padding logs in scope", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := open()
		if err != nil {
			return err
		}
		defer s.Close()
		if err = s.VerifyTaskArtifacts(cmd.Context(), verifyTask); err != nil {
			return err
		}
		count := 0
		for offset := 0; ; offset += 1000 {
			page, err := s.ArtifactPage(cmd.Context(), verifyTask, offset, 1000)
			if err != nil {
				return err
			}
			count += len(page)
			if len(page) < 1000 {
				break
			}
		}
		return jsonOut(out, map[string]any{"verified": true, "artifacts": count, "task_id": verifyTask, "scope": "all extraction files and padding logs in selected tasks"})
	}}
	verify.Flags().StringVar(&verifyTask, "task", "", "Owner task ID; otherwise all tasks")
	cmd.AddCommand(verify)
	cmd.AddCommand(&cobra.Command{Use: "notes", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		s, err := open()
		if err != nil {
			return err
		}
		defer s.Close()
		notes, err := s.Investigation(cmd.Context())
		if err != nil {
			return err
		}
		return jsonOut(out, notes)
	}})
	var rule, entity, reason string
	allow := &cobra.Command{Use: "whitelist", Short: "Suppress a rule for one exact evidence entity, with an audit reason", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if rule == "" || entity == "" {
			return fmt.Errorf("--rule, --entity and --reason are required")
		}
		s, err := open()
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Allow(cmd.Context(), rule, entity, reason)
	}}
	allow.Flags().StringVar(&rule, "rule", "", "Rule ID")
	allow.Flags().StringVar(&entity, "entity", "", "Exact entity from a finding")
	allow.Flags().StringVar(&reason, "reason", "", "Investigator rationale")
	cmd.AddCommand(allow)
	return cmd
}
