# SPARC Tkinter Prototype Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Recommended execution: native in this session, subject to the user's plan review and method selection.

**Goal:** Build a restrained, standalone CustomTkinter desktop prototype with four interactive mock-data screens.

**Architecture:** A single CustomTkinter window owns navigation and shared in-memory demo state. Independent screen frames render that state and invoke local callbacks; no SPARC production modules are imported. Shared typography, colors, and layout helpers keep the screens coherent.

**Tech Stack:** Python >=3.10, CustomTkinter 6.0.0, standard-library unittest for behavior checks, and Pillow for screenshot capture only. The version was checked against [official PyPI metadata](https://pypi.org/project/customtkinter/) during planning.

**Spec:** [Approved design](../specs/2026-10-09-sparc-tkinter-prototype-design.md).

## Global Constraints

- Work only in `/home/harsh/SPARC/.worktrees/sparc-tkinter-redesign`, branch `feat/sparc-tkinter-redesign`.
- Put all prototype code and dependencies in `prototypes/tkinter/`; use this worktree's `.venv/`.
- No production GUI/dependency changes, backend imports, network activity, identity access, lab reads, or demo file exports.
- All authored visual widgets must be CustomTkinter; no standard Tkinter or ttk widgets.
- Explicitly initialize `System` appearance and the `blue` theme; offer System / Light / Dark.
- Sans-serif family: Segoe UI when available, Arial otherwise; heading 24 bold, subheading 16 bold, body 12 normal.
- Use `grid()` with `sticky="nsew"` and explicit row/column weights on expandable components; no authored `pack()` layouts.
- Minimum internal spacing: `padx=10, pady=5`; main frames: `padx=20, pady=20`.
- Initial window approximately 1180 by 780; minimum 760 by 600; initial screen Chat.
- Sidebar destinations: Connection, Chat, Audit, Analysis; persistent `Demo · Mock data` indicator.
- Neutral surfaces, one blue action accent, modest rounding, text alongside semantic colors.
- No gradients, glows, decorative illustrations/statistics, emoji navigation, nested cards, marketing language, or gratuitous animation.
- Mock state remains in memory and resets on restart; sample verification and timings must be labeled honestly.

## Review Focus

1. Empty/whitespace messages and sends after disconnect must not append a message: Task 1 behavior test, Task 2 UI check.
2. Invalid IPv4/port input must show an inline error without mutating connection state: Task 1 test, Task 3 UI check.
3. Long multiline messages and unbroken fingerprints must remain readable at 760 by 600: Task 4 capture/check.
4. Theme changes and repeated navigation must preserve session state and readable selected/focused controls: Task 4 interaction check.
5. Closing the window must not leave scheduled demo work running or touch real data: Task 4 lifecycle/isolation check.

## Files and ownership

Under `prototypes/tkinter/` create:

- `app.py`: initialization, persistent views, sidebar, shared refresh, resize routing, close.
- `theme.py`: paired light/dark colors, spacing, radii, explicit font hierarchy.
- `ui.py`: small shared helpers for labels, buttons, task sections, and labeled fields.
- `state.py`: fictional fixtures and local state transitions; no GUI imports.
- `views/__init__.py`, `views/chat.py`, `views/connection.py`, `views/audit.py`, `views/analysis.py`: screen components.
- `requirements.txt`: pinned CustomTkinter version; no installation of SPARC.
- `README.md`: setup, launcher, interactions, verification, and mock-only boundary.
- `tests/test_state.py`: a few meaningful transition checks using unittest.
- `verify_ui.py`: actual-widget smoke checks and captures, runnable with an existing/private display.
- `evidence/`: screenshots and a concise verification report; no real user data.

## Task 1: In-memory mock interactions

**Files:** Create `state.py`, `tests/test_state.py`.

**Interfaces:**
- `Message(id: int, direction: str, text: str, timestamp: str, status: str)` dataclass.
- `DemoState()` starts connected to fictional Bob, with a small sample conversation.
- Public state: `connected: bool`, `listening: bool`, `messages: list[Message]`, `pairing: str`, `endpoint: str`, `analysis_run: int`, `audit_verified: bool`.
- Methods: `send(text: str) -> Message | None`, `connect(host: str, port: str) -> None`, `disconnect() -> None`, `set_listening(active: bool) -> None`, `respond_to_pairing(approve: bool) -> None`, `verify_audit() -> dict`, `run_analysis() -> dict`.
- Invalid endpoints raise `ValueError`; empty/disconnected sends return `None`; no I/O. Audit/analysis result dictionaries include `sample: True`; analysis results include a numeric `run` counter and deterministic metric values.

- [ ] Write `test_send_requires_connection_and_nonempty_text`: whitespace does not append; disconnect then send does not append; reconnect and send appends exactly one outgoing message preserving the submitted text.
- [ ] Write `test_invalid_endpoint_preserves_state`: invalid IPv4, nonnumeric port, port 0, and port 65536 raise `ValueError` and leave endpoint/connection unchanged; a documentation IPv4 and port 47655 succeeds.
- [ ] Write `test_demo_transitions_are_local_and_repeatable`: listener toggles, approve/reject changes pairing, audit result is labeled sample, and analysis advances through a fixed result sequence.

Use these essential assertions in the corresponding unittest cases:

```python
state = DemoState()
before = len(state.messages)
self.assertIsNone(state.send("  \n"))
state.disconnect()
self.assertIsNone(state.send("hello"))
self.assertEqual(len(state.messages), before)
state.connect("192.0.2.24", "47655")
self.assertEqual(state.send("hello").text, "hello")
self.assertEqual(len(state.messages), before + 1)

for host, port in [("invalid", "47655"), ("192.0.2.24", "abc"),
                   ("192.0.2.24", "0"), ("192.0.2.24", "65536")]:
    snapshot = (state.connected, state.endpoint)
    with self.assertRaises(ValueError):
        state.connect(host, port)
    self.assertEqual((state.connected, state.endpoint), snapshot)

state.set_listening(True)
self.assertTrue(state.listening)
state.set_listening(False)
self.assertFalse(state.listening)
state.respond_to_pairing(True)
self.assertEqual(state.pairing, "approved")
state.respond_to_pairing(False)
self.assertEqual(state.pairing, "rejected")
self.assertTrue(state.verify_audit()["sample"])
first, second = state.run_analysis(), state.run_analysis()
self.assertTrue(first["sample"] and second["sample"])
self.assertEqual(second["run"], first["run"] + 1)
```

- [ ] Run `python3 -m unittest discover -s tests -v` from `prototypes/tkinter`; confirm failure from missing `state`.
- [ ] Implement the dataclasses, fictional fixtures, and transitions; validate IPv4 with the standard-library `ipaddress` module. Use documentation address ranges, fictional 64-character fingerprints, and deterministic sample metrics. Retain full text while refusing whitespace-only input.
- [ ] Run the same command; require all behavior checks passing.
- [ ] Commit only the prototype state and behavior-check files on the redesign branch.

## Task 2: Responsive shell and Chat

**Files:** Create `requirements.txt`, `app.py`, `theme.py`, `ui.py`, `views/__init__.py`, `views/chat.py`, initial `README.md`, and initial `verify_ui.py`.

**Interfaces:**
- `PrototypeApp(state: DemoState | None = None)` subclasses `CTk`; methods `show_view(name: str) -> None`, `refresh_views() -> None`, `set_appearance(mode: str) -> None`, `close() -> None`.
- Each view subclasses `CTkFrame`, constructed as `(parent, state: DemoState, on_change: Callable[[], None])`; exposes `refresh() -> None`, `reflow(width: int) -> None`.
- Chat is `ChatView`; selecting a message updates its mock metadata inspector.
- `theme.initialize() -> None` sets appearance/theme; `theme.font(role: str) -> CTkFont` returns one of the three exact typography roles.

- [ ] Pin `customtkinter==6.0.0` in the prototype requirements. Create a private `.venv` and install only the prototype requirements. Confirm the imported version; do not install/edit SPARC or reuse the other agent's environment. If this release cannot be obtained, report the issue before selecting a different pin.
- [ ] Add an actual-widget smoke case asserting initial Chat visibility, shared state identity, and presence of `Demo · Mock data`; add empty-send/disconnected-send UI checks. Run on an available display and confirm it fails before the shell exists. If no display is available, prepare a private virtual display under this worktree or `/tmp`, with no system-package mutation.
- [ ] Implement tokens, helpers, sidebar, and persistent view ownership. Use neutral paired colors, 6-8 pixel radii, and the approved fonts/spacing. Handle a missing display with a concise launch error.
- [ ] Implement Chat history, selectable mock message metadata, composer, and Send. Use distinct alignment without extra status-card clutter. Update Send availability from shared state; empty input never appends. Bind Ctrl+Return to send while preserving ordinary multiline entry.
- [ ] Reflow Chat below 1000 pixels of window width: inspector below history, composer still reachable, history independently scrollable. Wrap long message/fingerprint strings based on available content width.
- [ ] Run the state tests and shell/Chat smoke checks; capture Chat in light/dark at 1180 by 780 and 760 by 600. Confirm the composer remains visible and the conversation survives refresh.
- [ ] Document `python app.py` launched from `prototypes/tkinter` using the private environment. Commit the shell/Chat deliverable.

## Task 3: Connection, Audit, and Analysis views

**Files:** Create `views/connection.py`, `views/audit.py`, `views/analysis.py`; extend `app.py` and `verify_ui.py`.

**Interfaces:**
- `ConnectionView`, `AuditView`, `AnalysisView` follow Task 2's constructor and `refresh/reflow` contracts.
- Views mutate state only through Task 1's methods, then call `on_change`.
- `app.show_view` accepts exactly `Connection`, `Chat`, `Audit`, `Analysis`; all frames persist across switches.

- [ ] Extend GUI smoke checks: all four destinations are reachable; Connection disconnect disables Chat Send; invalid endpoint shows an error and retains state; valid connect restores Send; listener and both pairing responses update their labels; audit/analysis simulation buttons change their sample results.
- [ ] Run the extended smoke checks; confirm failure for the missing destinations/interactions.
- [ ] Implement Connection as flat task groups for local listener, peer endpoint, identity approval, and remembered peers. Use full mock fingerprints with wrapping; show local validation errors inline. Pairing approval/rejection is simulated and labeled accordingly.
- [ ] Implement Audit as a short event list plus separate sample writer-head and sample verification summary. The primary button says `Simulate verification`; no file picker/export.
- [ ] Implement Analysis with compact sample-run controls and a simple result grid for sensitivity, timings, and resources. The primary button says `Simulate run`. Label values as samples; no actual measurements or decorative charts.
- [ ] Reflow Connection task groups and Analysis result columns below 1000-pixel window width; keep long screens scrollable and controls keyboard reachable.
- [ ] Run state and extended GUI checks; require every destination and interaction to pass. Commit the complete four-screen prototype.

## Task 4: Visual verification, isolation, and delivery

**Files:** Finish `verify_ui.py`, `README.md`; create `evidence/verification.md` and screenshots.

**Interfaces:**
- `python verify_ui.py --output evidence` exercises the real app and writes captures; nonzero exit on failed interaction/geometry checks.
- Capture filenames: `{view}-{light|dark}-{wide|compact}.png`, with lowercase view names; additional stress Chat captures.
- Capture tooling may use Pillow and a private display; prototype runtime itself must never write evidence or other data.

- [ ] Complete real-widget checks for repeated navigation/theme switching, draft/history preservation, visible composer, actual wide/compact geometry, long multiline text, long fingerprints, and close. Do not assert CTk's internal implementation or reject the internal Tk widgets it owns.
- [ ] Check isolation by exercising the app with backend imports and socket creation guarded, and using only explicit fictional fixtures. Inspect authored imports and file operations; distinguish verification-tool screenshot writes from runtime behavior.
- [ ] Run `python -m unittest discover -s tests -v` and `python verify_ui.py --output evidence` in the private environment/display. Capture all four screens, both themes, both sizes: 16 screenshots plus Chat stress captures.
- [ ] Inspect the images in one batched visual pass. Check clipping, contrast, hierarchy, spacing, selected/focused states, mock labeling, and whether extra containers earn their place. Fix observed defects together, then perform at most one confirmation pass.
- [ ] Record actual commands, outputs, screenshot matrix, platform, and any unavailable checks in `evidence/verification.md`; never report unperformed checks as passing.
- [ ] Finish README with exact setup/launch commands, keyboard interaction, state-reset behavior, evidence links, and mock-only scope.
- [ ] Run `git diff --check` and inspect the changed-path list; changes must be limited to prototype and its design/plan files. Run the applicable whole-branch review using the selected execution workflow, then resolve material findings.
- [ ] Commit the final verified prototype and evidence on its own branch. Deliver launcher instructions, a representative screenshot, and verification limits. Do not merge or launch against real lab data.

## Planning self-review

- Spec coverage: all four screens, state transitions, themes, typography, spacing, responsive stacking, isolation, launcher, and screenshot matrix are assigned above.
- Interfaces: all views share one state object and the same refresh/reflow contract; only the shell initializes appearance and routes shared refresh.
- Review focus: empty sends/invalid endpoints are checked at state and UI levels; long content/theme/navigation/close/isolation are assigned to Task 4.
- Scope: no backend adapter, production migration, real verification, or installer work is included.
- Execution is pending user review of this plan and selection of native or subagent-driven work.
