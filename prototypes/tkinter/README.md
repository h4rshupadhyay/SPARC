# SPARC visual prototype

A standalone CustomTkinter layout experiment with fictional peers and in-memory
messages. It does not run SPARC services or read identities, lab data, or audits.

From this worktree's root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r prototypes/tkinter/requirements.txt
.venv/bin/python prototypes/tkinter/app.py
```

Use the sidebar to navigate. Change the appearance using System / Light / Dark.
Enter sends on a new line; Ctrl+Enter sends the message. Click a message or use
the Message details selector to inspect fictional metadata. Restarting resets
all sample data.

This prototype is intentionally separate from the production GUI. It is not
ready for real networking or cryptographic verification.
