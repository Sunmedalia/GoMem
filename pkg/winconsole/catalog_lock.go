package winconsole

import (
	"context"
	"path/filepath"
	"sync"
)

type catalogLock struct {
	gate chan struct{}
	refs int
}

var catalogLocks = struct {
	sync.Mutex
	entries map[string]*catalogLock
}{entries: map[string]*catalogLock{}}

// Lock the complete check/download/publish transaction. On Windows a reader
// can prevent replacement or removal, so even verified cache reads must finish
// before a competing resolver mutates the same entry. Waits are cancellable;
// inactive paths are removed rather than accumulating per-case locks forever.
func acquireCatalog(ctx context.Context, path string) (func(), error) {
	key, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	catalogLocks.Lock()
	entry := catalogLocks.entries[key]
	if entry == nil {
		entry = &catalogLock{gate: make(chan struct{}, 1)}
		catalogLocks.entries[key] = entry
	}
	entry.refs++
	catalogLocks.Unlock()
	unref := func() {
		catalogLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(catalogLocks.entries, key)
		}
		catalogLocks.Unlock()
	}
	select {
	case entry.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-entry.gate
			unref()
			return nil, err
		}
		return func() { <-entry.gate; unref() }, nil
	case <-ctx.Done():
		unref()
		return nil, ctx.Err()
	}
}
