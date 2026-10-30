# Decoder exit confirmation regression

Final dark-UI verification exposed an existing intermittent capture-processing
failure: `test_malformed_capture_exits_1` returned success for a malformed
capture. The run had1196passes/9platformskips and this one failure; the isolated
rerun passed. No traffic source had changed in the UI task at that point.

Installed PyShark0.6 source explains the race. Its packet reader treats stdout
EOF as completion. Its cleanup kills a process whose return code is still
unset. Async child exit notification can arrive after stdout EOF, so cleanup
can replace the natural failing exit with its own kill and the adapter can
mistake the resulting empty stream for success.

Two deterministic tests reproduced the behavior before the correction: a child
whose natural exit is delivered after EOF was cleaned up before its status
was observed, for both exit0 and exit2. The corrected supervisor waits for
natural exit before accepting ordinary EOF, polls cancellation and bounds this
confirmation to the existing two-second cleanup budget. Nonzero exit fails
parsing; timeout is cleanup uncertainty. The single cleanup owner still runs.
Additional timeout/cancel cases pass within their declared bounded deadlines.

## Compatibility decision

PyShark0.6 exposes no public child-exit result. The local FileCapture subclass
therefore overrides the pinned private `_get_tshark_process` seam solely to
retain the returned public asyncio Process. Process creation, arguments and
packet parsing stay PyShark-owned. The supervisor uses Process.wait; it does
not inspect PyShark's private process collections or add a second decode pass.

This is an explicit exception to the original all-public-PyShark-API rule.
The alternative would be an additional whole-capture validation pass or a
replacement parser. The narrow compatibility seam preserves one-pass indexing
and makes the observed child exit part of completion. PyShark is already pinned
to0.6; changing that version requires rechecking this seam and the lifecycle
regressions. No claim is made that timeout proves native termination.

The affected adapter, real fixture stream/export and traffic CLI gate passed
41tests in6.59s. The four deterministic exit/timeout/cancellation cases passed
in0.28s. A separate real-tool repetition checks20malformed imports and a valid
empty PCAP, distinguishing decoder failure from legitimate zero packets.
The real-tool repetition passed: all20malformed captures were rejected without
reports, while a valid empty PCAP produced a successful zero-packet report.
Final full verification passed **1201tests /9native Windows-only skips in
194.32seconds**, exit0 without warnings. See
[appearance evidence](dark-appearance-evidence.md) for the exact command/log.
