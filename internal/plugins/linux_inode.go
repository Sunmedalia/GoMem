package plugins

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Sunmedalia/GoMem/pkg/evidence"
	"github.com/Sunmedalia/GoMem/pkg/object"
	"github.com/Sunmedalia/GoMem/pkg/plugin"
)

// Linux stores POSIX mode bits, not Go's os.FileMode flags.
func linuxMode(mode uint64) (string, string) {
	kind, marker := "", byte('?')
	switch mode & 0170000 {
	case 0010000:
		kind, marker = "FIFO", 'p'
	case 0020000:
		kind, marker = "CHR", 'c'
	case 0040000:
		kind, marker = "DIR", 'd'
	case 0060000:
		kind, marker = "BLK", 'b'
	case 0100000:
		kind, marker = "REG", '-'
	case 0120000:
		kind, marker = "LNK", 'l'
	case 0140000:
		kind, marker = "SOCK", 's'
	}
	text := []byte{marker, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	for n, c := range []byte("rwxrwxrwx") {
		if mode&(1<<uint(8-n)) != 0 {
			text[n+1] = c
		}
	}
	for _, special := range []struct {
		bit          uint64
		index        int
		lower, upper byte
	}{{04000, 3, 's', 'S'}, {02000, 6, 's', 'S'}, {01000, 9, 't', 'T'}} {
		if mode&special.bit != 0 {
			if text[special.index] == 'x' {
				text[special.index] = special.lower
			} else {
				text[special.index] = special.upper
			}
		}
	}
	return kind, string(text)
}

// Keep exact seconds/nanoseconds beside UTC, including epoch zero and negative
// Unix seconds. The reference's float/positive-only display is not raw data.
func linuxInodeTimestamp(ctx context.Context, e plugin.Environment, inode uint64, member string) (evidence.Value, evidence.Value, error) {
	var seconds int64
	var nanos uint64
	var err error
	secField, nsField := "", ""
	if _, er := e.Objects.Field("inode", member+"_sec"); er == nil {
		secField, nsField = member+"_sec", member+"_nsec"
	} else if !errors.Is(er, object.ErrFieldAbsent) {
		err = er
	} else {
		for _, field := range []string{"__" + member, member} {
			if _, er := e.Objects.Field("inode", field); er == nil {
				secField, nsField = field+".tv_sec", field+".tv_nsec"
				break
			} else if !errors.Is(er, object.ErrFieldAbsent) {
				err = er
				break
			}
		}
	}
	if err == nil && secField == "" {
		err = fmt.Errorf("no supported inode timestamp layout for %s", member)
	}
	if err == nil {
		seconds, err = e.Objects.Int(ctx, inode, "inode", secField)
	}
	if err == nil {
		nanos, err = e.Objects.Uint(ctx, inode, "inode", nsField)
	}
	if err != nil {
		v := evidence.Missing("inode_timestamp_unreadable", err)
		return v, v, err
	}
	proof := evidence.Value{Kind: "structure", Data: map[string]string{"seconds": strconv.FormatInt(seconds, 10), "nanoseconds": strconv.FormatUint(nanos, 10), "seconds_field": secField, "nanoseconds_field": nsField}}
	if nanos >= 1000000000 || seconds < -62135596800 || seconds > 253402300799 {
		err = fmt.Errorf("inode timestamp outside valid nanosecond/UTC range")
		return evidence.Missing("invalid_inode_timestamp", err), proof, err
	}
	return evidence.Text(time.Unix(seconds, int64(nanos)).UTC().Format(time.RFC3339Nano)), proof, nil
}

func linuxInodeMetadata(ctx context.Context, e plugin.Environment, file, dentry uint64) (map[string]evidence.Value, error) {
	cells := map[string]evidence.Value{}
	keys := []string{"InodeOffset", "InodeSource", "Inode", "Type", "Mode", "ModeRaw", "Size", "Device", "Major", "Minor", "Superblock", "Nlink", "Deleted", "Changed", "ChangedRaw", "Modified", "ModifiedRaw", "Accessed", "AccessedRaw"}
	for _, key := range keys {
		cells[key] = evidence.Missing("inode_not_set", nil)
	}
	var failures pluginFailures
	inode := uint64(0)
	source := "dentry.d_inode"
	if _, err := e.Objects.Field("file", "f_inode"); err == nil {
		var er error
		inode, er = e.Objects.Uint(ctx, file, "file", "f_inode")
		if er != nil {
			failures.add(er)
		}
		if inode != 0 {
			source = "file.f_inode"
		}
	} else if !errors.Is(err, object.ErrFieldAbsent) {
		failures.add(err)
	}
	if inode == 0 && dentry != 0 {
		var er error
		inode, er = e.Objects.Uint(ctx, dentry, "dentry", "d_inode")
		failures.add(er)
	}
	if inode == 0 {
		if err := failures.err("inode pointer"); err != nil {
			for _, key := range keys {
				cells[key] = evidence.Missing("inode_pointer_unreadable", err)
			}
			return cells, err
		}
		return cells, nil
	}
	metadata, err := linuxReadInodeMetadata(ctx, e, inode, source)
	return metadata, errors.Join(failures.err("inode pointer"), err)
}

func linuxReadInodeMetadata(ctx context.Context, e plugin.Environment, inode uint64, source string) (map[string]evidence.Value, error) {
	cells := map[string]evidence.Value{}
	for _, key := range []string{"InodeOffset", "InodeSource", "Inode", "Type", "Mode", "ModeRaw", "Size", "Device", "Major", "Minor", "Superblock", "Nlink", "Deleted", "Changed", "ChangedRaw", "Modified", "ModifiedRaw", "Accessed", "AccessedRaw"} {
		cells[key] = evidence.Missing("inode_not_set", nil)
	}
	var failures pluginFailures
	cells["InodeOffset"], cells["InodeSource"] = evidence.Address(inode), evidence.Text(source)
	u := func(key, typ, field string, address bool, base uint64) {
		value, err := e.Objects.Uint(ctx, base, typ, field)
		if err != nil {
			cells[key] = evidence.Missing("inode_metadata_unreadable", err)
			failures.add(err)
		} else if address {
			cells[key] = evidence.Address(value)
		} else {
			cells[key] = evidence.Number(value)
		}
	}
	u("Inode", "inode", "i_ino", false, inode)
	u("ModeRaw", "inode", "i_mode", false, inode)
	if mode, err := cells["ModeRaw"].Uint(); err == nil {
		kind, text := linuxMode(mode)
		cells["Mode"] = evidence.Text(text)
		cells["Type"] = evidence.Text(kind)
		if kind == "" {
			cells["Type"] = evidence.Missing("unknown_inode_type", nil)
		}
	} else {
		cells["Mode"], cells["Type"] = cells["ModeRaw"], cells["ModeRaw"]
	}
	size, err := e.Objects.Int(ctx, inode, "inode", "i_size")
	if err != nil {
		cells["Size"] = evidence.Missing("inode_metadata_unreadable", err)
		failures.add(err)
	} else {
		cells["Size"] = evidence.Integer(size)
	}
	links, err := linuxMember(ctx, e, inode, "inode", "i_nlink", "__i_nlink")
	if err != nil {
		cells["Nlink"], cells["Deleted"] = evidence.Missing("inode_metadata_unreadable", err), evidence.Missing("inode_metadata_unreadable", err)
		failures.add(err)
	} else {
		cells["Nlink"], cells["Deleted"] = evidence.Number(links), evidence.Value{Kind: "bool", Data: links == 0}
	}
	u("Superblock", "inode", "i_sb", true, inode)
	if sb, err := cells["Superblock"].Uint(); err == nil && sb != 0 {
		dev, err := e.Objects.Uint(ctx, sb, "super_block", "s_dev")
		if err != nil {
			cells["Device"] = evidence.Missing("device_unreadable", err)
			failures.add(err)
		} else {
			major, minor := dev>>20, dev&0xfffff
			cells["Major"], cells["Minor"], cells["Device"] = evidence.Number(major), evidence.Number(minor), evidence.Text(fmt.Sprintf("%d:%d", major, minor))
		}
	} else if err != nil {
		cells["Device"] = cells["Superblock"]
	}
	for _, stamp := range []struct{ column, field string }{{"Changed", "i_ctime"}, {"Modified", "i_mtime"}, {"Accessed", "i_atime"}} {
		var err error
		cells[stamp.column], cells[stamp.column+"Raw"], err = linuxInodeTimestamp(ctx, e, inode, stamp.field)
		failures.add(err)
	}
	return cells, failures.err("inode metadata")
}
