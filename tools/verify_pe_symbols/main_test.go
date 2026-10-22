package main

import "testing"

func TestGroupedAcquisitionBoundaries(t *testing.T) {
	valid := map[string]any{"method": "exports", "grouped": true, "acquisitions": []map[string]any{{"offset": "0x1000", "requested": uint64(1), "captured": uint64(1)}, {"offset": "0x1001", "requested": uint64(2), "captured": uint64(2)}}}
	calls, method, err := readCalls(valid, 0x1000, 3, 3, true)
	if err != nil || method != "exports" || len(calls) != 2 || calls[1].Offset != 0x1001 || calls[1].Requested != 2 {
		t.Fatal(calls, method, err)
	}
	for _, mode := range []string{"gap", "missing-bytes", "failed", "partial", "too-many", "wrong-method", "unmarked"} {
		detail := map[string]any{"method": "exports", "grouped": true, "acquisitions": []map[string]any{{"offset": "0x1000", "requested": uint64(1), "captured": uint64(1)}, {"offset": "0x1001", "requested": uint64(2), "captured": uint64(2)}}}
		success := true
		switch mode {
		case "gap":
			detail["acquisitions"].([]map[string]any)[1]["offset"] = "0x1002"
		case "missing-bytes":
			detail["acquisitions"].([]map[string]any)[1]["captured"] = uint64(1)
			detail["acquisitions"].([]map[string]any)[1]["requested"] = uint64(1)
		case "failed":
			success = false
		case "partial":
			detail["acquisitions"].([]map[string]any)[1]["captured"] = uint64(0)
		case "too-many":
			detail["acquisitions"] = make([]map[string]any, 65)
		case "wrong-method":
			detail["method"] = "opcode"
		case "unmarked":
			detail["grouped"] = false
		}
		if _, _, err := readCalls(detail, 0x1000, 3, 3, success); err == nil {
			t.Fatal("accepted damaged boundary list", mode)
		}
	}
}
