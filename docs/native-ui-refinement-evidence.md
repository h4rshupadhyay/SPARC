# Native UI refinement evidence

Date: 2026-10-30, Asia/Kolkata. Workspace: `.worktrees/sparc-progress-check`.
Execution and review are solo. No protocol, trust-policy or dependency changes; no merge or push.

## Resulting behavior

- Chat has an instructional empty conversation, separate Peer/You and status headings, a labelled compact composer, Attach image beside Send, and Ctrl+Enter sending. A connected peer endpoint is displayed when the live public service snapshot supplies it.
- Security details are optional. Explicit message selection opens a labelled inspector, while background messages update retained evidence without forcing it open. Inspector resizing preserves readable width and recomputes long wrapped ciphertext scroll extents. Drafts, receipt state and image acceptance controls retain their semantics.
- Native appearance is shared at the Tk root: stable body/heading fonts, restrained surfaces, primary action emphasis and high-contrast focus/selection. Image previews explicitly use their chat's Tk interpreter. The same fonts survive other peer windows closing.
- Connection leads with peer controls and full immutable fingerprints before listener/interface inventory. Approval still exposes the complete identities. Existing focus-to-scroll behavior keeps lower controls reachable.
- Audit explicitly starts Not verified. Verification produces a captured-prefix result, separately from the raw durable writer snapshot. Writer hashes/timing remain available through a labelled disclosure; head refresh does not overwrite the verification summary or scope.
- Analysis has one local row: Experiments, Performance, Avalanche, Details, Operation metrics. The experiment selector shows the relevant form and retains inputs. Completed runs still reveal their own result category. Separate category retention, CSV ownership and SVG provenance remain intact. Chart fonts and measured wrapping use the shared native scale; larger windows get a larger graph area.

## Automated checks

- Baseline before this refinement: 1129 passed, 11 inherited traffic failures, 10 skipped. Chat/image/app baseline: 27 passed.
- Task 1: three new UI/appearance tests observed failing before implementation. Chat/image/app/refinement gate: 30 passed in 11.56 s.
- Task 2: two new peer-order/audit-summary tests observed failing before implementation. Connection/audit/status gate: 45 passed in 12.53 s.
- Task 3: two direct-navigation/experiment-selection tests observed failing before implementation. Adapted obsolete nested-tab and default-font assumptions to the actual new native layout/font.
- Broader GUI and plot gate: 126 passed, 2 existing-style Tk Variable finalizer warnings in 71.88 s. Warnings occurred during identity-unlock tests (`main thread is not in main loop`); the baseline had previously exhibited this finalizer warning. They are not treated as a clean warning-free run.
- Inspector width after resize and hidden-tab image-offer reachability were reproduced with failing regression tests and fixed. The existing long-ciphertext scrollbar test caught lazy Tk wrap geometry and passed after its extent sync was tied to resize. Final targeted resize/scroll checks: 3 passed in 0.76 s; hidden-offer/long-ciphertext checks: 2 passed in 0.71 s.
- Avoiding forced layout for hidden history/inspectors retains the same data and fixes wasted work: 500-message history, long-ciphertext inspection and compact offer checks passed in 2.79 s; history case 2.40 s.

## Native acceptance

`.demo/ui-refinement-evidence/native_smoke.py` runs production GUI views against two authenticated localhost PeerServices with temporary identities. It exercised actual GUI text sends and verified receipts, an incoming image's inline Accept and save action, original/recovered byte equality, thumbnails, optional security inspection, audit verification, focused experiment selection, measured local benchmarks and avalanche/SVG results. Both peers remained connected and shared the same root-owned body font.

Eleven screenshots and measured SVGs are retained in `.demo/ui-refinement-evidence/`: empty/populated Chat, compact image offer, recovered image inspector, Connection, unverified/verified Audit, Experiments, ordinary/wide Performance and Avalanche. Sizes: 800x640, 1200x1000 and 2600x1400. Native chart text bounds had no horizontal clipping. The visual defect pass corrected inspector width, compact offer scrolling, field font scaling and inactive selection contrast. Subsequent work was limited to those concrete regressions and their verification.

Native keyboard selection, Ctrl+Enter binding and labelled disclosures use Tk controls. Full screen-reader behavior, other operating systems and physical LAN delivery were not verified. UI refinement does not establish cryptographic security or an unconditional GUI-completeness claim.

## Final verification

Full `.venv/bin/python -m pytest -q`: **1138 passed, 11 failed, 10 skipped in 189.10 s**. There were no GUI failures or warning summary in this final run. The failures match the earlier, untouched traffic baseline:

- `test_sqlite_index.py::test_public_import_hash_is_bounded_and_cancellable`
- `test_traffic_exports.py::test_export_uses_exact_unfiltered_argv_and_file_streams`
- `test_traffic_exports.py::test_valid_pdml_and_empty_document_publish_actual_packet_count` (2 cases)
- `test_traffic_exports.py::test_invalid_pdml_preserves_selected_output_and_cleans_staging` (2 cases)
- `test_traffic_exports.py::test_nonzero_child_error_is_safe_and_preserves_output`
- `test_traffic_exports.py::test_pre_cancel_does_not_mutate_source_or_selected_output`
- `test_traffic_exports.py::test_source_destination_alias_is_rejected_before_process` (3 cases)

The final targeted native compact regression reran actual peer text/image/audit/chart flows and updated the two affected screenshots. Accept and save / Reject are now visible after a hidden-tab resize, and the recovered-image inspector has readable width, text selection contrast and full scroll extent. `compact-regression.log` reports PASS and exact byte equality.

The updated peer demo uses a separate `.demo/ui-peer-session.json` and temporary encrypted identities. Both peers are connected, both graph categories are prepared, and Chat displays real verified demo messages. The earlier demo is preserved rather than restarted, to retain any in-memory user draft/history. No external peer or account was contacted.
