package explore

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/Sunmedalia/GoMem/pkg/memory"
)

func (s *Session) translate(ctx context.Context, args []string, w io.Writer) error {
	if len(args) != 2 {
		return fmt.Errorf("translate ADDRESS")
	}
	address, err := strconv.ParseUint(args[1], 0, 64)
	if err != nil {
		return err
	}
	if err := s.Engine.ValidateSource(ctx); err != nil {
		return err
	}
	if virtual, ok := s.Layer.(*memory.Virtual); ok {
		t, err := virtual.Resolve(ctx, address)
		if err != nil {
			return err
		}
		kind := "physical"
		if t.Pagefile != nil {
			kind = fmt.Sprintf("pagefile:%d", *t.Pagefile)
		}
		if _, err := fmt.Fprintf(w, "%s @ %#x -> %s offset=%#x available=%#x page-size=%#x entry=%#x entry-address=%#x entry-width=%d permissions-known=%t\n", s.Layer.Name(), address, kind, t.Offset, t.Available, t.PageSize, t.Entry, t.EntryAddress, t.EntryWidth, t.PermissionsKnown); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(w, "%s @ %#x (physical layer coordinate)\n", s.Layer.Name(), address); err != nil {
			return err
		}
	}
	return s.Engine.ValidateSource(ctx)
}
