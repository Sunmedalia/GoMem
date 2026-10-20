// Package triage evaluates explicit evidence prerequisites. An unavailable check
// is reported as unavailable, never as an absence of suspicious activity.
package triage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Sunmedalia/GoMem/internal/engine"
	"github.com/Sunmedalia/GoMem/internal/version"
	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

var ErrIncomplete = errors.New("triage coverage incomplete; inspect unavailable checks")

type Rule struct {
	ID, Severity, Basis, FalsePositive string
	Inputs                             []string
	Kind                               string
}

var Rules = []Rule{
	{"hidden-process", "high", "A scanned process object is absent from the active list by object address; PID alone is not compared.", "Terminated or partially acquired process objects can differ from the active list.", []string{"pslist", "psscan"}, "difference"},
	{"executable-writable-region", "high", "An executable mapping also permits writes.", "JIT runtimes and unpackers can legitimately use writable executable memory.", []string{"maps"}, "rwx"},
	{"module-enumeration-difference", "medium", "A scanned module object is absent from the loaded-module list by object address.", "Unloaded modules and stale pool allocations may remain in RAM.", []string{"modules", "modscan"}, "difference"},
	{"deleted-or-memfd-execution", "high", "A mapping explicitly marked executable references a deleted file or memfd.", "Package upgrades, containers and legitimate in-memory software can produce these mappings.", []string{"maps"}, "deleted"},
	{"persistence-process-link", "medium", "A persistence record explicitly references the same address-based process identity.", "Authorized startup software is common; validate the configuration owner and command.", []string{"persistence", "pslist"}, "persistence"},
	{"literal-ioc", "medium", "An exact configured literal occurs at the recorded physical offset.", "Literal strings may occur in caches, logs, inactive buffers or security software.", []string{"ioc"}, "ioc"},
}

type Check struct {
	Rule     string `json:"rule"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
}
type Summary struct {
	State       string          `json:"state"`
	Checks      []Check         `json:"checks"`
	Tasks       []engine.Result `json:"tasks"`
	FindingTask string          `json:"finding_task,omitempty"`
	Findings    int             `json:"findings"`
}

// Evaluate consumes normalized plugin rows. Every finding references raw evidence
// IDs and inherits that evidence's image, layer, offset and symbol identity.
func Evaluate(ctx context.Context, r Rule, inputs map[string][]evidence.Row, emit plugin.Emit) error {
	for _, key := range r.Inputs {
		if _, ok := inputs[key]; !ok {
			return fmt.Errorf("rule %s requires %s", r.ID, key)
		}
		for _, row := range inputs[key] {
			if err := row.Verify(); err != nil {
				return err
			}
		}
	}
	finding := func(row evidence.Row, entity string, refs []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if row.ID == "" || row.Provenance.ImageSHA256 == "" {
			return fmt.Errorf("rule input lacks sealed evidence provenance")
		}
		cells := map[string]evidence.Value{"Rule": evidence.Text(r.ID), "Severity": evidence.Text(r.Severity), "Basis": evidence.Text(r.Basis), "FalsePositive": evidence.Text(r.FalsePositive), "Entity": evidence.Text(entity), "EvidenceIDs": {Kind: "references", Data: refs}}
		p := row.Provenance
		p.Plugin = "triage." + r.ID
		out := evidence.Row{Cells: cells, Provenance: p}
		out.Seal()
		return emit(out)
	}
	switch r.Kind {
	case "ioc":
		for _, row := range inputs["ioc"] {
			if err := finding(row, row.ID, []string{row.ID}); err != nil {
				return err
			}
		}
	case "difference":
		known := make(map[string]bool)
		for _, row := range inputs[r.Inputs[0]] {
			key, err := objectKey(row)
			if err != nil {
				return err
			}
			known[key] = true
		}
		for _, row := range inputs[r.Inputs[1]] {
			key, err := objectKey(row)
			if err != nil {
				return err
			}
			if !known[key] {
				if err = finding(row, key, []string{row.ID}); err != nil {
					return err
				}
			}
		}
	case "rwx", "deleted":
		for _, row := range inputs["maps"] {
			hit := false
			if r.Kind == "rwx" {
				if _, err := required(row, "Protection"); err != nil {
					return err
				}
				protection := strings.ToLower(row.Cells["Protection"].String())
				hit = strings.Contains(protection, "rwx") || strings.EqualFold(protection, "page_execute_readwrite")
			} else {
				if _, err := required(row, "Path"); err != nil {
					return err
				}
				if _, err := required(row, "Executable"); err != nil {
					return err
				}
				path := row.Cells["Path"].String()
				hit = row.Cells["Executable"].String() == "true" && (strings.HasPrefix(path, "memfd:") || strings.HasPrefix(path, "/memfd:") || strings.HasSuffix(path, " (deleted)"))
			}
			if hit {
				identity, err := required(row, "ProcessIdentity")
				if err != nil {
					return err
				}
				if err := finding(row, identity.String(), []string{row.ID}); err != nil {
					return err
				}
			}
		}
	case "persistence":
		identities := make(map[string]evidence.Row)
		for _, row := range inputs["pslist"] {
			value, err := required(row, "Identity")
			if err != nil {
				return err
			}
			id := value.String()
			if id != "" {
				identities[id] = row
			}
		}
		for _, row := range inputs["persistence"] {
			value, err := required(row, "ProcessIdentity")
			if err != nil {
				return err
			}
			id := value.String()
			if proc, ok := identities[id]; ok && proc.Provenance.ImageSHA256 == row.Provenance.ImageSHA256 {
				if err := finding(row, id, []string{row.ID, proc.ID}); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unknown triage rule kind %s", r.Kind)
	}
	return nil
}
func required(row evidence.Row, name string) (evidence.Value, error) {
	v, ok := row.Cells[name]
	if !ok || v.Kind == "missing" || v.Data == nil || v.String() == "" {
		return v, fmt.Errorf("rule input %s has no readable %s", row.ID, name)
	}
	return v, nil
}
func objectKey(row evidence.Row) (string, error) {
	a, ok := row.Cells["Offset"]
	if !ok || a.Kind != "address" || row.Provenance.ImageSHA256 == "" || row.Provenance.Layer == "" {
		return "", fmt.Errorf("enumeration evidence lacks object address, image or layer")
	}
	if _, err := a.Uint(); err != nil {
		return "", err
	}
	return row.Provenance.ImageSHA256 + ":" + row.Provenance.Layer + ":" + a.String(), nil
}

func Run(ctx context.Context, e *engine.Engine, needles []string) (summary Summary, err error) {
	summary.State = "incomplete"
	os := e.Env.OS
	if os != "linux" && os != "windows" {
		return summary, fmt.Errorf("triage requires --os linux or windows")
	}
	tasks := map[string]evidence.Task{}
	failures := map[string]string{}
	names := map[string]string{"pslist": os + ".pslist", "modules": "windows.modules"}
	if os == "linux" {
		names["modules"] = "linux.lsmod"
	}
	for _, key := range []string{"pslist", "modules"} {
		res, runErr := e.Run(ctx, names[key], nil, engine.RunOptions{})
		if runErr != nil {
			failures[key] = runErr.Error()
		} else {
			tasks[key] = res.Task
		}
		if res.Task.ID != "" {
			summary.Tasks = append(summary.Tasks, res)
		}
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
	}
	var iocTasks []evidence.Task
	for _, needle := range needles {
		res, runErr := e.Run(ctx, "generic.ioc", map[string]string{"needle": needle}, engine.RunOptions{})
		if runErr != nil {
			failures["ioc"] = runErr.Error()
		} else {
			iocTasks = append(iocTasks, res.Task)
		}
		if res.Task.ID != "" {
			summary.Tasks = append(summary.Tasks, res)
		}
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
	}
	b, _ := json.Marshal(summary.Tasks)
	hash := sha256.Sum256(b)
	task, err := e.Store.Begin(ctx, "triage:"+hex.EncodeToString(hash[:]), "triage", evidence.Provenance{ImageSHA256: e.Hash, Engine: version.Version, EngineBuild: e.Build, Plugin: "triage", Layer: e.Env.Physical.Name(), Parameters: map[string]string{"rules": "v1"}})
	if err != nil {
		return summary, err
	}
	summary.FindingTask = task.ID
	// Rules execute a page at a time. Difference rules keep only object keys in
	// the evaluator when invoked independently; unsupported inputs remain explicit.
	for _, rule := range Rules {
		check := Check{Rule: rule.ID, State: "unavailable"}
		available := true
		inputs := map[string][]evidence.Row{}
		for _, key := range rule.Inputs {
			if key == "ioc" {
				if len(needles) == 0 {
					available = false
					check.Reason = "no --ioc literals configured"
					break
				}
				if failures[key] != "" {
					available = false
					check.Reason = failures[key]
					break
				}
				inputs[key] = nil
				continue
			}
			if t, ok := tasks[key]; ok {
				_ = t
				inputs[key] = nil
			} else {
				available = false
				check.Reason = failures[key]
				if check.Reason == "" {
					check.Reason = "native input plugin for " + key + " is not implemented"
				}
				break
			}
		}
		if available {
			if rule.Kind == "ioc" {
				check.State = "completed"
				for _, input := range iocTasks {
					for off := 0; ; off += 500 {
						rows, readErr := e.Store.Query(ctx, evidence.Query{TaskID: input.ID, Offset: off, Limit: 500})
						if readErr != nil {
							err = readErr
							break
						}
						evalErr := Evaluate(ctx, rule, map[string][]evidence.Row{"ioc": rows}, func(row evidence.Row) error {
							allowed, allowErr := e.Store.Allowed(ctx, rule.ID, row.Cells["Entity"].String())
							if allowErr != nil {
								return allowErr
							}
							if allowed {
								return nil
							}
							if appendErr := e.Store.Append(ctx, task.ID, []evidence.Row{row}); appendErr != nil {
								return appendErr
							}
							check.Findings++
							summary.Findings++
							return nil
						})
						if evalErr != nil {
							err = evalErr
							break
						}
						if len(rows) < 500 {
							break
						}
					}
					if err != nil {
						break
					}
				}
			} else {
				check.Reason = "required normalized evidence pipeline is not implemented"
				available = false
			}
		}
		if err != nil {
			check.State = "failed"
			check.Reason = err.Error()
		}
		summary.Checks = append(summary.Checks, check)
		if err != nil {
			break
		}
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err == nil {
		for _, check := range summary.Checks {
			if check.State != "completed" {
				err = ErrIncomplete
				break
			}
		}
	}
	state := "completed"
	if err != nil {
		state = "failed"
	}
	err = errors.Join(err, e.Store.Finish(cleanup, task.ID, state, err))
	if err != nil {
		return summary, err
	}
	summary.State = "completed"
	return summary, nil
}
