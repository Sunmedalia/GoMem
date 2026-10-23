# Shimcache layouts

These twelve JSON fragments are copied byte-for-byte from Volatility 3
v2.28.2 at commit `881e970121c16f0932fb9d16fbd5fb258cbcbf75`.

Source directory:

```text
volatility3/framework/symbols/windows/shimcache/
```

They define the on-disk structure variants used by the pinned
`windows.shimcachemem.ShimcacheMem` plugin. GoMem embeds them so the native
analysis runtime does not depend on Python, Volatility, or a checkout of the
upstream source tree. They contain no executable code. The upstream files are
distributed under the Volatility Software License 1.0; see the repository's
`LICENSES/Volatility-Software-License-1.0.txt` for the license text.

The fixed oracle scripts independently verify these bytes and their behavior.
Do not edit a layout to accommodate a parser or sample. A changed layout needs
an updated baseline, source digest, tests, and validation record.
