package plugins

import (
	"context"
	"fmt"

	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/wingui"
)

// GUI constraints are separate from the kernel's built-ins. Their object body
// sizes and validity belong to the selected GUI layout, not the kernel ISF.
func guiPoolConstraints(layout *wingui.Layout, tags ...string) ([]poolConstraint, error) {
	if layout == nil || layout.Types == nil || layout.Types.PointerSize() != 8 {
		return nil, fmt.Errorf("GUI pool scan requires a matching x64 layout")
	}
	all := []poolConstraint{
		{tag: []byte("Wind"), typeName: "tagWINDOWSTATION", objectType: "WindowStation", minSize: 0x90, hasMin: true, pageType: poolPaged | poolNonPaged, skipType: true},
		{tag: []byte("Desk"), typeName: "tagDESKTOP", objectType: "Desktop", pageType: poolPaged | poolNonPaged, skipType: true},
	}
	for i := range all {
		c := &all[i]
		if _, err := layout.Types.Type(c.typeName); err != nil {
			return nil, err
		}
		c.objectTable = layout.Types
		desktop := c.typeName == "tagDESKTOP"
		c.valid = func(ctx context.Context, scan *object.Reader, at uint64) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			reader := wingui.Reader{Layout: layout, Layer: scan.Layer}
			var valid bool
			var err error
			if desktop {
				valid, err = reader.DesktopValid(ctx, at)
			} else {
				valid, err = reader.StationValid(ctx, at)
			}
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			// The original validity methods suppress invalid-address exceptions. The
			// acquisition layer must retain these failed reads independently, so one
			// bad candidate does not prevent later objects from being recovered.
			if err != nil {
				return false, nil
			}
			return valid, nil
		}
	}
	if len(tags) == 0 {
		return all, nil
	}
	want := map[string]bool{}
	for _, tag := range tags {
		want[tag] = true
	}
	result := []poolConstraint{}
	for _, c := range all {
		if want[string(c.tag)] {
			result = append(result, c)
			delete(want, string(c.tag))
		}
	}
	if len(want) != 0 {
		return nil, fmt.Errorf("unknown GUI pool tag")
	}
	return result, nil
}
