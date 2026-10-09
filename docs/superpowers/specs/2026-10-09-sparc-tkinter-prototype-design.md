# SPARC desktop visual prototype

Date: 2026-10-09
Status: Written design awaiting review before implementation planning.

## Purpose and agreed scope

Build a standalone, runnable CustomTkinter prototype that lets the user evaluate
SPARC's desktop appearance and core interactions. The user selected mock data,
approved sidebar navigation, and requested a restrained design that avoids
generic AI dashboard styling. The prototype is exploratory; it does not replace
the current application.

Success means the four screens are coherent, readable, resize comfortably, and
have working simulated controls. The user can inspect both light and dark
appearances without creating identities or running SPARC services.

## Isolation

- Worktree: `.worktrees/sparc-tkinter-redesign`.
- Branch: `feat/sparc-tkinter-redesign`, based on committed `main` at `ade2abc`.
- Put the prototype in `prototypes/tkinter/` with its own requirements and README.
- Use a virtual environment belonging to this worktree.
- Do not edit production GUI modules or production dependency declarations.
- Do not import SPARC backend services, discover network interfaces, open sockets,
  read lab data, load identities, or access audit/checkpoint files.
- Keep mock state in memory; restarting resets the demonstration.
- Do not change the other agent's worktree, branch, processes, or environment.

## Visual direction

Choose a quiet desktop utility, with a persistent left sidebar, a clear page
heading, and one primary action for each task. Open Chat initially.

Use neutral surfaces, readable contrast, a single blue action accent, and modest
corner radii. Reserve semantic colors for statuses and pair them with text.
Avoid gradients, glows, decorative illustrations, oversized statistics,
gratuitous animations, emoji navigation, nested cards, and marketing language.
Use spacing and alignment for ordinary layout; use a panel only when it groups
an independent task. Preserve the sidebar approved by the user while applying
the relevant simplification ideas from Impeccable's distill reference.

All authored visual widgets must be CustomTkinter; no standard Tkinter or ttk
widgets. Explicitly initialize `System` appearance and the `blue` theme. Provide
a System / Light / Dark selector near the bottom of the sidebar. Underlying
Tcl/Tk support used by CustomTkinter is expected and is not a widget exception.

Use one explicit sans-serif family, Segoe UI when available and Arial otherwise.
The typography scale is heading 24 bold, subheading 16 bold, and body 12 normal.
Define shared tokens for these fonts, colors, spacing, and radii.

Use `grid()` for authored layouts, with `sticky="nsew"` and explicit row/column
weights on expandable components. Minimum internal spacing is `padx=10,
pady=5`; main frames use `padx=20, pady=20`. Avoid pack-based authored layouts.

## Shell and responsive behavior

Start at approximately 1180 by 780 pixels, with a minimum of 760 by 600.
The sidebar contains SPARC, Connection, Chat, Audit, Analysis, the appearance
selector, and a persistent `Demo · Mock data` indicator. The main area expands.

At narrower widths, Chat's message inspector moves below the conversation.
Connection's task panels and Analysis's result columns stack vertically.
Use CustomTkinter scrolling containers where content exceeds the available
height. Keep the message composer reachable, wrap long fingerprints and text,
and preserve keyboard access to navigation and controls.

## Screens and simulated behavior

### Chat

Show a fictional conversation with Bob, distinct incoming/outgoing alignment,
short timestamps, and delivery text explicitly presented as sample data.
Provide a composer and Send action. Nonempty input appends a local demo message;
empty input does not create a message. Show Send unavailable while disconnected.
Selecting a message shows its mock public metadata in a secondary inspector.
Preserve conversation state while navigating between screens.

### Connection

Group local listener controls, peer connection, identity approval, and remembered
peers into simple task areas. Use fictional addresses and fingerprints only.
Start/stop and connect/disconnect update shared mock state and Chat availability.
Validate the shape of editable endpoints locally and show concise inline errors.
An incoming approval example can be approved or rejected without network calls.

### Audit

Show a short list of fictional audit events and a readable sample verification
summary. A `Simulate verification` action updates the mock result. Distinguish
the sample writer head from the sample verification result. Do not offer a file
picker, export files, or imply that a real chain was verified.

### Analysis

Show compact controls for a sample analysis run and readable result rows for
sensitivity, timings, and resources. A `Simulate run` action cycles deterministic
sample results with an honest mock label. These are not measured benchmarks.
Use simple result bars or text rows when useful, rather than decorative charts
or extra plotting dependencies.

## Structure

Keep the standalone entrypoint, visual tokens, in-memory demo state, and screen
views separate. Shared mock state is the sole source of connection and message
state across screens. Keep callbacks on the Tk UI thread. Use bounded scheduled
callbacks only if a simulation needs a short delay, and cancel them on close.
Expose a documented command to start the prototype from its directory.

## Verification and delivery

- Verify all four navigation destinations and state preservation.
- Exercise connect/disconnect, listener controls, pairing, empty/nonempty Send,
  sample audit verification, and sample analysis results.
- Capture and inspect all screens in light and dark appearances at the initial
  size and a compact size, including a long-message/fingerprint case.
- Confirm that authored widgets, spacing, fonts, and geometry meet the rules.
- Check that starting and interacting with the prototype does not touch real
  identities, lab data, backend services, or production modules.
- Deliver the launcher instructions and screenshot artifacts with any limits
  of verification stated explicitly.

## Out of scope

Backend integration, production GUI migration, real identity unlock, real
cryptographic verification, network transport, file export, packet capture,
actual benchmarks, packaging installers, and merging into the active agent's
branch. Integration is a later task after the design has been evaluated.
