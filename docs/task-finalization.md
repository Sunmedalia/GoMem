# Task finalization on slow case storage

Windows CI run `39712277765` exposed an engine finalization deadline rather than
an analysis mismatch: the Linux call-stack `x64/signal/invalid-sp` control emitted
the expected empty findings, eleven read captures and one summary, then returned
`context deadline exceeded` while updating its terminal state.

Previously, artifact finalization, the remaining evidence batch and terminal
state shared one ten-second context. Filesystem scanning and slow SQLite writes
could consume that budget before the state write began. Evidence/artifact
finalization now has a one-minute budget and the terminal update gets its own
one-minute context. Both remain independent of user cancellation so partial
evidence can be committed after an interrupted analysis. These are bounded
cleanup operations, not analysis time limits.

Persistence errors still propagate. A failed terminal update is explicitly
reported as `persist terminal task state` and the returned task is failed; it is
not described as a completed analysis. If the database itself cannot accept the
terminal update, its persisted task can remain running until normal recovery;
this change does not claim durable success in that condition.

The existing call-stack differential, partial-failure retry, cancellation
retention and close-waits-for-commit tests cover the affected execution path.
The observed slow Windows control is rechecked by the native CI job.
