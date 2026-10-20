package plugins

import "testing"

func TestLinuxRelativeSymlinkMatchesBaselineParentWalk(t *testing.T) {
	cases := []struct{ source, target, want string }{
		{source: "/link", target: "evidence.bin", want: "evidence.bin"},
		{source: "/link", target: "/etc/passwd", want: "etc/passwd"},
		{source: "/dir/link", target: "/etc/passwd", want: "../etc/passwd"},
		{source: "/a/b/link", target: "/etc/passwd", want: "../../etc/passwd"},
		{source: "/dir/link", target: "/dir/file", want: "../dir/file"},
		{source: "/link", target: "/", want: "."},
		{source: "/dir/link", target: "/", want: ".."},
		{source: "/a/b/link", target: "/", want: "../.."},
		{source: "/link", target: "/etc//passwd/", want: "etc/passwd"},
	}
	for _, tc := range cases {
		if got := linuxRelativeSymlink(tc.source, tc.target); got != tc.want {
			t.Fatalf("%s -> %s: got %q want %q", tc.source, tc.target, got, tc.want)
		}
	}
}
