// Package acceptance enforces the release contract against the embedded matrix.
package acceptance

import (
	"encoding/json"
	"fmt"

	"github.com/Sunmedalia/GoMem/docs"
	"github.com/Sunmedalia/GoMem/internal/version"
)

type entry struct {
	ID, Status, Comparison string
	Accepted               bool
	Corpora                []string
}
type Report struct {
	PluginCount           int  `json:"plugin_count"`
	AcceptedPlugins       int  `json:"accepted_plugins"`
	PendingInfrastructure int  `json:"pending_infrastructure"`
	Ready                 bool `json:"ready"`
}

func Inspect() (Report, error) {
	var m struct {
		Schema                  string
		Baseline                struct{ Version, Commit string }
		PluginCount             int `json:"plugin_count"`
		Plugins, Infrastructure []entry
	}
	var r Report
	if err := json.Unmarshal(docs.Capabilities, &m); err != nil {
		return r, err
	}
	if m.Schema != "gomem.capabilities/v1" || m.Baseline.Commit != version.BaselineCommit || m.Baseline.Version != version.Baseline {
		return r, fmt.Errorf("acceptance baseline mismatch")
	}
	if len(m.Plugins) == 0 || m.PluginCount != len(m.Plugins) {
		return r, fmt.Errorf("invalid upstream plugin count")
	}
	seen := map[string]bool{}
	accepted := func(e entry) (bool, error) {
		if e.ID == "" || seen[e.ID] {
			return false, fmt.Errorf("empty or duplicate capability %q", e.ID)
		}
		seen[e.ID] = true
		if e.Accepted && (e.Status != "complete" || e.Comparison != "passed" || len(e.Corpora) == 0) {
			return false, fmt.Errorf("capability %s claims acceptance without implementation, corpus and comparison", e.ID)
		}
		return e.Accepted, nil
	}
	for _, e := range m.Plugins {
		ok, err := accepted(e)
		if err != nil {
			return r, err
		}
		if ok {
			r.AcceptedPlugins++
		}
	}
	for _, e := range m.Infrastructure {
		ok, err := accepted(e)
		if err != nil {
			return r, err
		}
		if !ok {
			r.PendingInfrastructure++
		}
	}
	r.PluginCount = len(m.Plugins)
	r.Ready = r.AcceptedPlugins == r.PluginCount && r.PendingInfrastructure == 0 && len(m.Infrastructure) > 0
	return r, nil
}
