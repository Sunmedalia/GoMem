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

var ErrIncomplete = errors.New("triage coverage incomplete; inspect check states and coverage")

type Rule struct {
	ID, Severity, Basis, FalsePositive string
	Inputs                             []string
	Kind                               string
}

var Rules = []Rule{
	{"hidden-process", "high", "A scanned task candidate is absent from the active task/thread list by object coordinates; PID alone is not compared.", "Exited tasks, stale allocations and partial acquisitions can differ from the active list; exited candidates are informational.", []string{"pslist", "psscan"}, "difference"},
	{"executable-writable-region", "high", "A mapping has direct read/write/execute protection.", "JIT runtimes and unpackers can legitimately use writable executable memory.", []string{"maps"}, "rwx"},
	{"module-enumeration-difference", "medium", "A scanned module object is absent from the loaded-module list by object address.", "Unloaded modules and stale pool allocations may remain in RAM.", []string{"modules", "modscan"}, "difference"},
	{"deleted-or-memfd-execution", "high", "A mapping explicitly marked executable references a deleted file or memfd.", "Package upgrades, containers and legitimate in-memory software can produce these mappings.", []string{"maps"}, "deleted"},
	{"persistence-process-link", "medium", "A persistence record explicitly references the same address-based process identity.", "Authorized startup software is common; validate the configuration owner and command.", []string{"persistence", "pslist"}, "persistence"},
	{"literal-ioc", "medium", "An exact configured literal occurs at the recorded physical offset.", "Literal strings may occur in caches, logs, inactive buffers or security software.", []string{"ioc"}, "ioc"},
	{"suspicious-thread-start", "high", "A live thread entry maps to a VAD with no readable file path, unexpected initial protection, or another executable path; addresses are checked once per process.", "JIT, legitimate unpackers and acquisition smear may trigger this check. An unreadable path does not prove that a mapping has no file.", []string{"suspicious_threads"}, "native-check"},
	{"hollow-process-mapping", "high", "The native PEB image base differs from the kernel section base, the executable VAD is missing, or an executable/loader DLL VAD has unexpected initial protection.", "Legitimate loaders, modified mappings, exiting processes and acquisition smear may differ. These checks alone do not establish process hollowing.", []string{"hollowprocesses"}, "native-check"},
	{"peb-string-length", "info", "A nonempty native PEB string has Length/2 or MaximumLength/2-1 different from its decoded Unicode codepoint count.", "Embedded NUL, legitimate buffer allocation, Unicode surrogate pairs and acquisition smear can explain this length indicator. Correlate kernel names and raw bytes before assessing masquerading.", []string{"pebmasquerade"}, "native-check"},
}

func ruleForPlatform(rule Rule, platform string) Rule {
	if platform == "windows" && rule.ID == "deleted-or-memfd-execution" {
		rule.Kind = "native-check"
		rule.Inputs = []string{"processghosting"}
		rule.Basis = "An active user process has a null/unreadable image file object, an image file marked DeletePending, or a named nonprivate VAD has deletion-related file/control flags. VAD deletion alone does not establish execution."
		rule.FalsePositive = "Legitimate file replacement, deleted mappings, acquisition smear and unreadable file objects can trigger these signals. Correlate the raw image, VAD and file object before assessing process ghosting."
	}
	if platform == "windows" && rule.ID == "module-enumeration-difference" {
		rule.Kind = "module-difference"
		rule.Basis = "A pool-scanned loader object is absent from the loaded-module list by object coordinates; the case workflow compares physical backing, never names or executable base addresses."
	}
	if platform == "windows" && rule.ID == "hidden-process" {
		rule.Kind = "native-check"
		rule.Inputs = []string{"psxview"}
		rule.Basis = "A valid process object is collected by a pool, thread-owner or csrss handle view but absent from the active process list at the same numeric object offset; PID alone is not compared."
		rule.FalsePositive = "Exited processes, stale allocations, per-view filters and partial acquisitions can differ. A view mismatch alone does not prove process hiding."
	}
	return rule
}

type Check struct {
	Rule     string            `json:"rule"`
	State    string            `json:"state"`
	Reason   string            `json:"reason,omitempty"`
	Findings int               `json:"findings"`
	Coverage map[string]string `json:"coverage,omitempty"`
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
		return emitFinding(ctx, r, row, entity, refs, emit)
	}
	switch r.Kind {
	case "module-difference":
		evaluator := moduleViewEvaluator{rule: r}
		if err := evaluator.consume(ctx, inputs["modules"], false, emit); err != nil {
			return err
		}
		if err := evaluator.consume(ctx, inputs["modscan"], true, emit); err != nil {
			return err
		}
		_, err := evaluator.finish()
		return err
	case "native-check":
		if len(r.Inputs) != 1 {
			return fmt.Errorf("invalid native triage rule inputs")
		}
		evaluator := nativeCheckEvaluator{rule: r}
		if err := evaluator.consume(ctx, inputs[r.Inputs[0]], emit); err != nil {
			return err
		}
		_, err := evaluator.finish()
		return err
	case "ioc":
		for _, row := range inputs["ioc"] {
			if err := finding(row, row.ID, []string{row.ID}); err != nil {
				return err
			}
		}
	case "difference":
		known := &differenceIndex{objects: map[string]bool{}}
		for _, row := range inputs[r.Inputs[0]] {
			if err := known.add(r, row); err != nil {
				return err
			}
		}
		return evaluateDifferenceRows(ctx, r, known, inputs[r.Inputs[1]], emit)
	case "rwx", "deleted":
		for _, row := range inputs["maps"] {
			hit := false
			if r.Kind == "rwx" {
				if numeric, ok := row.Cells["ProtectionValue"]; ok {
					value, err := numeric.Uint()
					if err != nil || row.Cells["Protection"].Kind != "string" {
						return fmt.Errorf("rule input %s has unreadable or unknown mapping protection", row.ID)
					}
					hit = value&0x40 != 0 // PAGE_EXECUTE_READWRITE, including modifiers.
				} else {
					if _, err := required(row, "Protection"); err != nil {
						return err
					}
					protection := strings.ToLower(row.Cells["Protection"].String())
					hit = strings.Contains(protection, "rwx")
					for _, name := range strings.Split(protection, "|") {
						hit = hit || name == "page_execute_readwrite"
					}
				}
			} else {
				if _, err := required(row, "Executable"); err != nil {
					return err
				}
				if value := row.Cells["Executable"].String(); value != "true" && value != "false" {
					return fmt.Errorf("invalid mapping executable state")
				}
				if row.Cells["Executable"].String() == "false" {
					continue
				}
				if _, err := required(row, "Path"); err != nil {
					return err
				}
				path := row.Cells["Path"].String()
				memfd := strings.HasPrefix(path, "memfd:") || strings.HasPrefix(path, "/memfd:")
				deleted := strings.HasSuffix(path, " (deleted)")
				if _, ok := row.Cells["Deleted"]; ok && !memfd {
					value, err := required(row, "Deleted")
					if err != nil {
						return err
					}
					if value.String() != "true" && value.String() != "false" {
						return fmt.Errorf("invalid mapping deletion state")
					}
					deleted = value.String() == "true"
				}
				hit = memfd || deleted
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
	if _, ok := row.Cells["PhysicalLayer"]; ok {
		if _, exists := row.Cells["PhysicalOffset"]; !exists {
			return "", fmt.Errorf("physical evidence has no physical offset")
		}
	}
	if physical, ok := row.Cells["PhysicalOffset"]; ok {
		layer, err := required(row, "PhysicalLayer")
		if err != nil {
			return "", err
		}
		address, err := physical.Uint()
		if err != nil || physical.Kind != "address" || layer.Kind != "string" || row.Provenance.ImageSHA256 == "" {
			return "", fmt.Errorf("evidence lacks readable physical object coordinates")
		}
		return fmt.Sprintf("%s:physical:%s:0x%x", row.Provenance.ImageSHA256, layer.String(), address), nil
	}

	a, ok := row.Cells["Offset"]
	if !ok || a.Kind != "address" || row.Provenance.ImageSHA256 == "" || row.Provenance.Layer == "" {
		return "", fmt.Errorf("enumeration evidence lacks object address, image or layer")
	}
	if _, err := a.Uint(); err != nil {
		return "", err
	}
	address, _ := a.Uint()
	return fmt.Sprintf("%s:virtual:%s:0x%x", row.Provenance.ImageSHA256, row.Provenance.Layer, address), nil
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
	order := []string{"pslist", "modules"}
	if os == "linux" {
		names["modules"] = "linux.lsmod"
	}
	names["maps"] = "windows.vadinfo"
	if os == "linux" {
		names["maps"] = "linux.maps"
	}
	order = append(order, "maps")
	if os == "linux" {
		names["psscan"] = "linux.psscan"
		order = append(order, "psscan")
	} else {
		names["modscan"] = "windows.modscan"
		names["pebmasquerade"] = "windows.pebmasquerade"
		names["processghosting"] = "windows.processghosting"
		names["psxview"] = "windows.psxview"
		names["suspicious_threads"] = "windows.suspicious_threads"
		names["hollowprocesses"] = "windows.hollowprocesses"
		order = append(order, "modscan", "psxview", "suspicious_threads", "hollowprocesses", "processghosting", "pebmasquerade")
	}
	for _, key := range order {
		var parameters map[string]string
		if key == "pslist" && os == "linux" {
			parameters = map[string]string{"threads": "true"}
		}
		res, runErr := e.Run(ctx, names[key], parameters, engine.RunOptions{})
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
	task, err := e.Store.Begin(ctx, "triage:"+hex.EncodeToString(hash[:]), "triage", evidence.Provenance{ImageSHA256: e.Hash, Engine: version.Version, EngineBuild: e.Build, Plugin: "triage", Layer: e.Env.Physical.Name(), Parameters: map[string]string{"rules": "v7"}})
	if err != nil {
		return summary, err
	}
	summary.FindingTask = task.ID
	// Rules execute a page at a time. Difference rules keep only object keys in
	// the evaluator when invoked independently; unsupported inputs remain explicit.
	for _, rule := range Rules {
		rule = ruleForPlatform(rule, os)
		check := Check{Rule: rule.ID, State: "unavailable"}
		if rule.Kind == "native-check" && os != "windows" {
			check.State, check.Reason = "not_applicable", "Windows-only native check"
			summary.Checks = append(summary.Checks, check)
			continue
		}
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
		emit := func(row evidence.Row) error {
			allowed, allowErr := e.Store.Allowed(ctx, rule.ID, row.Cells["Entity"].String())
			if allowErr != nil {
				return allowErr
			}
			if allowed {
				return nil
			}
			if rule.Kind == "difference" || rule.Kind == "module-difference" {
				model := "same image and address space; physical coordinates when declared"
				if rule.Kind == "module-difference" {
					model = "same image and physical backing of loader objects; source evidence unchanged"
				}
				row.Cells["Comparison"] = evidence.Value{Kind: "structure", Data: map[string]any{
					"active_task": comparisonTask(tasks[rule.Inputs[0]]), "scanned_task": comparisonTask(tasks[rule.Inputs[1]]),
					"coordinate_model": model,
				}}
				row.Seal()
			}
			if appendErr := e.Store.Append(ctx, task.ID, []evidence.Row{row}); appendErr != nil {
				return appendErr
			}
			check.Findings++
			summary.Findings++
			return nil
		}
		if available {
			if rule.Kind == "module-difference" {
				evaluator := moduleViewEvaluator{rule: rule, resolve: physicalModuleResolver(e.Env)}
				for index, key := range rule.Inputs {
					for off := 0; ; off += 500 {
						rows, readErr := e.Store.Query(ctx, evidence.Query{TaskID: tasks[key].ID, Offset: off, Limit: 500})
						if readErr != nil {
							err = readErr
							break
						}
						if err = evaluator.consume(ctx, rows, index == 1, emit); err != nil || len(rows) < 500 {
							break
						}
					}
					if err != nil {
						break
					}
				}
				if err == nil {
					var coverageErr error
					check.Coverage, coverageErr = evaluator.finish()
					check.State = "completed"
					if errors.Is(coverageErr, ErrIncomplete) {
						check.State, check.Reason = "incomplete", coverageErr.Error()
					} else if coverageErr != nil {
						err = coverageErr
					}
				}
			} else if rule.Kind == "native-check" {
				evaluator := nativeCheckEvaluator{rule: rule}
				input := tasks[rule.Inputs[0]]
				for off := 0; ; off += 500 {
					rows, readErr := e.Store.Query(ctx, evidence.Query{TaskID: input.ID, Offset: off, Limit: 500})
					if readErr != nil {
						err = readErr
						break
					}
					if err = evaluator.consume(ctx, rows, emit); err != nil || len(rows) < 500 {
						break
					}
				}
				if err == nil {
					var coverageErr error
					check.Coverage, coverageErr = evaluator.finish()
					check.State = "completed"
					if errors.Is(coverageErr, ErrIncomplete) {
						check.State, check.Reason = "incomplete", coverageErr.Error()
					} else if coverageErr != nil {
						err = coverageErr
					}
				}
			} else if rule.Kind == "ioc" || rule.Kind == "rwx" || rule.Kind == "deleted" && os == "linux" {
				inputTasks, inputKey := iocTasks, "ioc"
				if rule.Kind == "rwx" || rule.Kind == "deleted" {
					inputTasks, inputKey = []evidence.Task{tasks["maps"]}, "maps"
				}
				check.State = "completed"
				for _, input := range inputTasks {
					for off := 0; ; off += 500 {
						rows, readErr := e.Store.Query(ctx, evidence.Query{TaskID: input.ID, Offset: off, Limit: 500})
						if readErr != nil {
							err = readErr
							break
						}
						evalErr := Evaluate(ctx, rule, map[string][]evidence.Row{inputKey: rows}, emit)
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
			} else if rule.Kind == "difference" {
				check.State = "completed"
				known := &differenceIndex{objects: map[string]bool{}}
				for index, key := range rule.Inputs {
					input := tasks[key]
					for off := 0; ; off += 500 {
						rows, readErr := e.Store.Query(ctx, evidence.Query{TaskID: input.ID, Offset: off, Limit: 500})
						if readErr != nil {
							err = readErr
							break
						}
						if index == 0 {
							for _, row := range rows {
								if err = known.add(rule, row); err != nil {
									break
								}
							}
						} else {
							err = evaluateDifferenceRows(ctx, rule, known, rows, emit)
						}
						if err != nil || len(rows) < 500 {
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
			if check.State != "completed" && check.State != "not_applicable" {
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
