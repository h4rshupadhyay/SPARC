# SPARC

SPARC is a secure text communication and analysis application. The shared model,
encoding, local identity, peer trust, and diagnostic command are being built in
small milestones. The graphical chat interface is added in a later milestone.

Run the GUI-free local diagnostic with:

```sh
python -m sparc --check --data-dir ./sparc-data
```

The diagnostic creates or loads an Ed25519 identity in the selected directory,
then prints installed package versions and the public identity fingerprint. It
never prints the private key. Keep the data directory private and do not copy it
into exports or source control.

For normal installation, install the package and development extras with
`python -m pip install -r requirements-dev.txt`. Core runtime dependencies are
listed in `requirements.txt`.
