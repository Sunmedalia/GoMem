package plugins

import "fmt"

// callbackPoolConstraints describes the data-only x86/x64 callback layouts in
// the fixed baseline. Original factory and header-scanner controls validate
// these sizes and index endpoints independently of the native pool walker.
func callbackPoolConstraints(width int, vista bool) ([]poolConstraint, error) {
	if width != 4 && width != 8 {
		return nil, fmt.Errorf("callback layouts require 4- or 8-byte pointers")
	}
	shutdown, generic, notification := uint64(12), uint64(12), uint64(16)
	if width == 8 {
		shutdown, generic, notification = 24, 24, 48
	}
	pages := poolPaged | poolNonPaged | poolFree
	constraints := []poolConstraint{
		{tag: []byte("IoFs"), typeName: "_NOTIFICATION_PACKET", minSize: notification, hasMin: true, pageType: pages},
		{tag: []byte("IoSh"), typeName: "_SHUTDOWN_PACKET", minSize: shutdown, hasMin: true, pageType: pages},
		{tag: []byte("Cbrb"), typeName: "_GENERIC_CALLBACK", minSize: generic, hasMin: true, pageType: pages},
	}
	if vista {
		constraints = append(constraints,
			poolConstraint{tag: []byte("DbCb"), typeName: "_DBGPRINT_CALLBACK", minSize: 0x20, maxSize: 0x40, hasMin: true, hasMax: true, pageType: pages},
			poolConstraint{tag: []byte("Pnp9"), typeName: "_NOTIFY_ENTRY_HEADER", minSize: 0x30, hasMin: true, minIndex: 1, maxIndex: 1, pageType: pages},
			poolConstraint{tag: []byte("PnpD"), typeName: "_NOTIFY_ENTRY_HEADER", minSize: 0x40, hasMin: true, minIndex: 1, maxIndex: 1, pageType: pages},
			poolConstraint{tag: []byte("PnpC"), typeName: "_NOTIFY_ENTRY_HEADER", minSize: 0x38, hasMin: true, minIndex: 1, maxIndex: 1, pageType: pages},
		)
	}
	return constraints, nil
}
