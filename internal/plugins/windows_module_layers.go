package plugins

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/memory"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

type peLayerAttempt struct {
	Layer         string `json:"layer,omitempty"`
	ProcessOffset string `json:"process_offset,omitempty"`
	PID           string `json:"pid,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	Stage         string `json:"stage"`
	Error         string `json:"error,omitempty"`
}

type peSessionLayer struct {
	layer  memory.MemoryLayer
	source peLayerAttempt
}

type windowsModuleLayers struct {
	env            plugin.Environment
	max, maxLayers int
	built          bool
	candidates     []peSessionLayer
	diagnostics    []peLayerAttempt
	omitted        uint64
	err            error
}

func (s *windowsModuleLayers) build(ctx context.Context) {
	s.built = true
	seen := map[uint64]bool{}
	diagnostic := func(a peLayerAttempt) {
		if len(s.diagnostics) < 64 {
			s.diagnostics = append(s.diagnostics, a)
		} else {
			s.omitted++
		}
	}
	s.err = visitWindowsProcesses(ctx, s.env, s.max, nil, func(process, pid uint64, name string, created evidence.Value) error {
		a := peLayerAttempt{ProcessOffset: fmt.Sprintf("0x%x", process), PID: strconv.FormatUint(pid, 10), Stage: "session_identity"}
		id := windowsSessionID(ctx, s.env, process)
		if id.Reason == "not_applicable" {
			return nil
		}
		session, err := id.Uint()
		if err != nil {
			a.Error = id.String()
			diagnostic(a)
			return nil
		}
		if seen[session] {
			return nil
		}
		if len(s.candidates) >= s.maxLayers {
			return fmt.Errorf("session layer enumeration exceeds max-session-layers=%d", s.maxLayers)
		}
		a.SessionID = strconv.FormatUint(session, 10)
		stamp := ""
		if created.Kind != "missing" {
			stamp = created.String()
		}
		identity := evidence.ProcessID(s.env.ImageHash, s.env.Kernel.Name(), process, pid, stamp)
		layer, err := processMemory(ctx, s.env, process, 0, identity)
		if err != nil {
			a.Stage, a.Error = "process_address_space", err.Error()
			diagnostic(a)
			return nil
		}
		seen[session] = true
		a.Layer = layer.Name()
		s.candidates = append(s.candidates, peSessionLayer{layer, a})
		return nil
	})
}

func (s *windowsModuleLayers) find(ctx context.Context, base uint64) (memory.MemoryLayer, []peLayerAttempt, error) {
	var attempts []peLayerAttempt
	try := func(layer memory.MemoryLayer, a peLayerAttempt) bool {
		// Never choose a layer on a successful zero-length read. Strict header
		// parsing and PE validation still happen separately, before file creation.
		_, err := memory.Read(ctx, layer, base, 64)
		a.Stage = "dos_header_read"
		if err != nil {
			a.Error = err.Error()
		}
		attempts = append(attempts, a)
		return err == nil
	}
	if try(s.env.Kernel, peLayerAttempt{Layer: s.env.Kernel.Name()}) {
		return s.env.Kernel, attempts, nil
	}
	if ctx.Err() != nil {
		return nil, attempts, ctx.Err()
	}
	if !s.built {
		s.build(ctx)
	}
	attempts = append(attempts, s.diagnostics...)
	if s.omitted > 0 {
		attempts = append(attempts, peLayerAttempt{Stage: "diagnostic_limit", Error: fmt.Sprintf("%d additional session diagnostics omitted; no source bytes inferred", s.omitted)})
	}
	if s.err != nil {
		attempts = append(attempts, peLayerAttempt{Stage: "session_enumeration_incomplete", Error: s.err.Error()})
		return nil, attempts, s.err
	}
	for _, candidate := range s.candidates {
		if try(candidate.layer, candidate.source) {
			return candidate.layer, attempts, nil
		}
		if ctx.Err() != nil {
			return nil, attempts, ctx.Err()
		}
	}
	return nil, attempts, fmt.Errorf("no readable DOS header at %#x in kernel or %d verified session layers (%d session diagnostics)", base, len(s.candidates), len(s.diagnostics)+int(s.omitted))
}
