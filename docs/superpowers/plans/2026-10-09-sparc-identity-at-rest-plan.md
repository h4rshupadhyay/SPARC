# SPARC F1 Identity Encryption at Rest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Preserve the user's selected workflow below instead of silently substituting fresh implementers or self-run validation.

**Goal:** Encrypt persistent Ed25519 identities without changing their keys, fingerprints, trust or audit verification, with explicit safe unlock and cancellation.

**Architecture:** Use the pinned `cryptography` Argon2id/Fernet recipe around an in-memory PKCS8 serialization. Keep codec, identity-specific storage, identity lifecycle and startup adapters separate. GUI startup transfers an opaque validated unlocked-store handle into the service; public diagnostics never unlock or mutate.

**Tech Stack:** Python >=3.10; existing `cryptography==50.0.2`; Tk; Linux `fcntl`; Windows `msvcrt` and standard-library `ctypes` wrappers for Win32 security APIs; existing pytest. No dependency additions.

**Spec:** [Approved F1 design](../specs/2026-10-09-sparc-identity-at-rest-design.md). This plan is **awaiting user review** and authorizes no implementation until approved.

## Global Constraints

- Order: A3 → F1 → T1 → T2 → T3. A3 baseline `b53453b`; F1 remains pending until its milestone gates pass.
- One reused Luna writes each unit's prescribed tests, then implements that unit after the controller's meaningful RED result. The controller alone runs RED/GREEN commands, records actual outputs and performs the milestone commit. Sol reviews contracts and independently reviews F1 security/integration before that commit.
- Only the files enumerated for the active unit may change. No broad trust/audit, protocol, analysis or traffic refactor; no OS credential vault, passphrase rotation, recovery/reset, inactivity locking or defaults.
- Argon2id: `length=32`, `memory_cost=65536` KiB, `iterations=3`, `lanes=4`, fresh 16-byte CSPRNG salt, no `secret` or `ad`; Fernet decryption has no TTL. Unsupported backend/insufficient memory fails without a weaker fallback.
- Outer v2 fields exactly `version`, `public_key`, `encryption`, `kdf`, `encrypted_private_key`; `version=2`, `encryption="fernet"`; KDF fields exactly `name`, `salt`, `memory_cost`, `iterations`, `lanes`, `length`; `name="argon2id"`. Integers must reject Boolean values.
- Inner fields exactly `domain`, `header`, `private_key_pkcs8`; `domain="SPARC identity at rest v2"`; header copies every outer field except ciphertext. Authenticate, compare header, parse library DER PKCS8, require Ed25519, compare raw public key.
- File bound 4096 bytes (read at most 4097), token ASCII bound 2048, decrypted JSON bound 1024, decoded DER bound 128. Existing canonical/strict JSON helpers reject duplicates and malformed nesting.
- New/migrated text passphrases: >=15 Unicode characters, <=1024 UTF-8 bytes; library new/migrated byte credentials: >=15 bytes. Unlock: nonempty, <=1024 bytes. Strict UTF-8, no normalization/trimming/truncation. Creation/migration requires equal confirmation.
- No passphrase argv/env/files/logs/events/reports, stored derived keys/PHC verifiers, fixed production/simulation secrets, plaintext temp/backups or automatic identity regeneration on errors.
- Linux directory `0700`, identity/temp/lock `0600`; Windows identity-specific protected DACL with current user/LocalSystem, preserving tighter restrictions. Actual Windows evidence is pending until run; mocks do not establish platform correctness.
- Lock acquisition cancellation poll <=50 ms, deadline two seconds, safe `identity_busy` error. Locks contain no secrets; no stale-lock deletion. Do not hold them over human input or a KDF.
- Publication is irreversible at atomic replacement. Precommit failure preserves bytes; postcommit durability/readback failure is `identity_commit_uncertain`, with no rollback/replacement/regeneration. Canceled after publication retains the encrypted same key and prevents service construction.
- `--check` is read-only/public metadata only: no prompts, generation, migration, permission change, lock creation, service, Tk or optional tools. Normal analysis/traffic remain independent.

## Review Focus

1. Identity path becomes a dangling link/reparse point between inspection and publication: reject it instead of treating it as a new store (F1b/F1c).
2. Two simultaneous new-store/migration attempts have different credentials: one committed identity survives, loser receives `identity_changed` (F1b).
3. User cancels while a noninterruptible KDF is blocked: GUI remains responsive, cancellation is checked afterward, no service/networking starts (F1e).
4. Legacy private/public mismatch passes public diagnostics but must never migrate/start: diagnostics says unverified, lifecycle rejects before credentials/publication (F1c/F1f).
5. Simulation loses its coordinator during private credential delivery: bounded child exit and secret-free incomplete evidence, no surviving listeners/processes (F1g).

## Files and execution discipline

New production modules: `src/sparc/identity_codec.py` (credential/public types and encrypted codec), `src/sparc/identity_storage.py` (bounded reads/lock/publication), `src/sparc/_windows_identity_storage.py` (native security/file adapter), `src/sparc/identity_unlock.py` (terminal adapter), `src/sparc/gui/identity_unlock.py` (Tk startup dialog).

Existing `identity.py` keeps public lifecycle and TrustStore; change only identity lifecycle portions. Existing `storage.py`, audit/trust formats and signing interfaces remain unchanged. Existing `PeerService` factors its startup initialization only; its ongoing connection code remains unchanged.

Every task follows: Luna tests-only → controller RED → same Luna implementation → controller GREEN/affected checks → Sol bounded review → controller evidence entry. Do not commit intermediate tasks. Record command, exit/result, failing assertion for RED, and completed review in `docs/implementation-status.md` beneath the pending F1 mandate. For newly introduced modules/APIs, use safe `importlib` feature detection inside a test and an explicit assertion that the required API exists; do not import an absent module at collection time. A missing required API assertion is the initial contract RED for a new module; when an existing flow is reachable, run its concrete behavioral assertion and record that failure as well. Collection, fixture, infrastructure and unexpected import errors never count as meaningful RED: fix the prescribed tests and rerun. Expected results below are future gates, never claims that commands have run.

Commands run from `/home/harsh/SPARC/.worktrees/sparc-progress-check`, using `/home/harsh/SPARC/.venv/bin/python -m pytest`. If that interpreter is absent, stop for controller environment repair; do not install dependencies or silently switch environments.

## F1a — Credential contracts, bounded encrypted codec and metadata

**Allowed files:** Create `src/sparc/identity_codec.py`, `tests/unit/test_identity_codec.py`; controller evidence only in `docs/implementation-status.md`.

**Produces:**

```python
@dataclass(frozen=True)
class IdentityUnlockRequest:
    purpose: Literal["create", "migrate", "unlock"]
    data_dir: Path
    fingerprint: str | None = None  # unverified stored metadata
@dataclass(frozen=True)
class IdentityCredentials:
    passphrase: bytes = field(repr=False)
    confirmation: bytes | None = field(default=None, repr=False)
@dataclass(frozen=True)
class IdentityInfo:
    status: Literal["absent", "legacy_unencrypted", "encrypted_locked"]
    public_bytes: bytes | None
    fingerprint: str | None
    private_key_verified: bool = False
CredentialProvider = Callable[[IdentityUnlockRequest], IdentityCredentials | None]
CancelPredicate = Callable[[], bool]
def validate_credentials(value: IdentityCredentials, purpose: str) -> bytes: ...
def inspect_document(raw: bytes) -> IdentityInfo: ...
def encode_identity(identity: Identity, passphrase: bytes,
                    *, cancelled: CancelPredicate | None = None) -> bytes: ...
def decode_identity(raw: bytes, passphrase: bytes,
                    *, cancelled: CancelPredicate | None = None) -> Identity: ...
```

`inspect_document` validates exact outer schema/bounds/Base64 shape without Ed25519 private parsing or decryption, including v1 private-field shape but not its private/public correspondence. Empty/unsupported/malformed documents are `invalid_identity`. Cancellation is `identity_unlock_cancelled`; credential policy/type errors are `identity_credentials_invalid`; authenticated-decryption failure is `identity_unlock_failed`; unsupported backend/memory is `identity_crypto_unavailable`. Error messages are fixed summaries.

- [ ] Luna adds `test_codec_roundtrip_preserves_key_and_authenticates_header`, `test_codec_rejects_bounded_schema_before_kdf` (parameterized), `test_wrong_credentials_and_tampered_ciphertext_fail`, `test_credential_confirmation_and_repr`, `test_backend_failure_has_no_fallback`, `test_cancel_before_and_after_kdf`.

```python
assert recovered.public_bytes == original.public_bytes
assert recovered.fingerprint == original.fingerprint
assert recovered.private_key.sign(b"F1 continuity") == original.private_key.sign(b"F1 continuity")
assert set(document) == {"version", "public_key", "encryption", "kdf", "encrypted_private_key"}
assert document["kdf"]["memory_cost"] == 65536
assert document["kdf"]["iterations"] == 3 and document["kdf"]["lanes"] == 4
assert document["kdf"]["length"] == 32
assert private_raw not in encoded and base64.b64encode(private_raw) not in encoded
assert passphrase not in encoded and passphrase.decode("ascii") not in repr(credentials)
assert error.value.code == "identity_unlock_failed"
assert kdf_spy.call_count == 0  # oversized, invalid cost/type/schema, duplicate keys
```

Use random ASCII credentials derived from `secrets.token_hex(32).encode()`; tests of byte-only credentials use random bytes. Test salt length 16/freshness, exact header equality, non-Ed25519 authenticated payload, v1 mismatch metadata unverified, unsupported version, noncanonical token/salt/public Base64 and bounds 4097/2049/1025/129. Header/token failure tests require no plaintext release.

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_identity_codec.py -q`; expected missing prescribed API/roundtrip failure. Record actual result.
- [ ] Same Luna implements only this module, using library primitives and existing `encoding.canonical/parse_object`; no storage or prompts.
- [ ] Controller GREEN: same command; expected all pass. Sol verifies format and errors against the spec; controller records evidence.

## F1b — Identity-specific private reads, locking and publication

**Allowed files:** Create `src/sparc/identity_storage.py`, `src/sparc/_windows_identity_storage.py`, `tests/unit/test_identity_storage.py`, `tests/integration/test_identity_storage_races.py`, `tests/integration/test_identity_windows.py`; controller evidence only in `docs/implementation-status.md`. Do not modify shared `storage.py`.

**Consumes:** `CancelPredicate` from F1a; existing `storage._sync_parent_directory` or an equivalent identity-local helper with the same Linux behavior. **Produces:**

```python
def read_identity_file(path: Path) -> bytes | None: ...  # no mutation; absent only on ENOENT
def read_private_identity_file(path: Path, *, cancelled: CancelPredicate | None = None) -> bytes | None: ...
def publish_identity(path: Path, expected: bytes | None, candidate: bytes,
                     *, cancelled: CancelPredicate | None = None) -> None: ...
@contextmanager
def identity_lock(path: Path, *, cancelled: CancelPredicate | None = None) -> Iterator[None]: ...
# Private Windows adapter; imported only on Windows:
def prepare_private_directory(path: Path) -> None: ...
def secure_identity_file(path: Path) -> None: ...
def open_regular_file(path: Path) -> BinaryIO: ...
```

`read_identity_file` returns `None` only if no directory entry exists, using no-follow Linux open/fstat and Windows handle opened with `FILE_FLAG_OPEN_REPARSE_POINT`, then rejecting reparse/nonregular handles. Its bounded read never calls `Path.read_bytes`. Permissions are not modified by public read. Before resolving the private data-directory path, reject symlink/reparse components in the supplied data-directory path and its existing ancestors, and require the dedicated SPARC directory to belong to the current user. Verify opened directory/identity/lock handles refer to those inspected objects. The reusable `.identity.lock` must also be opened without following links, checked as a regular current-user-owned file, and rejected if dangling, linked, a reparse point or otherwise unsuitable; never replace/delete it as recovery. Private operations establish private modes/DACL before opening lock/temp, and report `data_permissions_failed` on failure.

Windows adapter uses `GetTokenInformation(TokenUser)` for the SID, security-descriptor retrieval/set APIs (`GetNamedSecurityInfoW`, `SetNamedSecurityInfoW`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree`) through `ctypes`; protect the DACL, restrict allow entries to current user/LocalSystem, retain narrower existing rights/denials, never install a NULL DACL. NTFS file/lock/temp handles must receive private ACLs before containing data. Directory restrictions apply only to the dedicated SPARC directory and F1-owned files, without rewriting individual trust/audit file ACLs or contents. Reject unowned/shared directories and unsupported ACL filesystems. Temporary files contain v2 ciphertext only.

`publish_identity` holds the two-second cancellable OS lock, rereads exact `expected` under it, creates/flushed/fsynced private temp, checks cancel/target once more, then replaces. Source change is `identity_changed`; precommit I/O is `identity_write_failed`; error after successful replace is `identity_commit_uncertain`. No rollback. Successful readback equals candidate. Clean only owned temp; keep `.identity.lock` (private nonsecret reusable lock). Expose narrow private `_replace`/`_sync_directory` helpers for fault injection without altering shared writers.

- [ ] Luna writes `test_read_is_bounded_read_only_and_rejects_links`, `test_private_modes_and_permission_failure`, `test_private_store_rejects_linked_lock_ancestors_and_unowned_directory`, `test_publication_preserves_original_before_commit`, `test_post_replace_error_is_uncertain_not_rollback`, `test_cancel_and_lock_timeout`, `test_two_process_create_and_migrate_compare_expected`, `test_windows_private_acl_and_reparse_rejection` (real Windows only). The linked-lock/ancestor test asserts the link target's bytes/permissions are untouched and no identity is published; the ownership test injects owner mismatch and asserts failure before chmod/DACL/lock creation.

```python
assert path.read_bytes() == before  # precommit injected failures/cancel/source mismatch
assert error.value.code == "identity_commit_uncertain"
assert path.read_bytes() == candidate  # injected directory sync error after replace
assert stat.S_IMODE(path.stat().st_mode) == 0o600  # real Linux
assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
assert outcomes.count("committed") == 1 and outcomes.count("identity_changed") == 1
assert path.read_bytes() in candidates
assert elapsed < 2.5 and error.value.code == "identity_busy"
assert all(temp.read_bytes().startswith(b'{') and b'"version":2' in temp.read_bytes()
           for temp in owned_temps_observed_before_replace)
```

Race tests use spawn child arguments containing candidate ciphertext only; no secret argv/env. Windows test inspects native DACL principals/protection, no group grant, failed ACL adjustment, retained denial, replacement with open handles and file/reparse rejection. Do not fake Windows execution by changing `sys.platform` around Win32 calls.

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_identity_storage.py tests/integration/test_identity_storage_races.py -q`; expected missing API or preservation assertion failure.
- [ ] Same Luna implements private storage/native adapter only.
- [ ] Controller GREEN: same command plus `tests/unit/test_identity.py::test_atomic_write_failure_preserves_existing_file`; expect pass and no shared-writer change. Actual Windows command is recorded in F1h; Linux skips are recorded as skips, not Windows PASS. Sol reviews race/commit boundaries.

## F1c — Create/load/migrate lifecycle and opaque startup handle

**Allowed files:** Modify `src/sparc/identity.py` identity-management portion only, `tests/unit/test_identity.py`; create `tests/conftest.py`, `tests/unit/test_identity_migration.py`; controller evidence only in `docs/implementation-status.md`.

**Consumes:** F1a codec/types, F1b read/private read/publication. Re-export credential/public types from `identity.py` for callers. **Produces:**

```python
def inspect_identity(data_dir: Path) -> IdentityInfo: ...
def load_identity(data_dir: Path, *, credential_provider: CredentialProvider | None = None,
                  cancelled: CancelPredicate | None = None) -> Identity: ...
def _unlock_store(data_dir: Path, *, credential_provider: CredentialProvider | None = None,
                  cancelled: CancelPredicate | None = None) -> _UnlockedStore: ...
def _consume_unlocked_store(handle: _UnlockedStore,
                            *, cancelled: CancelPredicate | None = None) -> tuple[Path, Identity]: ...
```

`_UnlockedStore` is private, opaque/redacted and single-use; contains resolved data directory/path, exact committed file bytes (v2), unlocked Identity, private issuer marker and consumed flag. Only `_unlock_store` issues it. `_consume_unlocked_store` checks exact type/issuer/unused, cancellation, current file equality under the identity lock, marks consumed and returns `(data_dir, identity)`; changed target is `identity_changed`, invalid/reused handle is `invalid_identity`. It never accepts an arbitrary `Identity`. `load_identity` returns the handle's identity without exporting the handle. The handoff is an internal misuse guard, not a security boundary against code running in the same Python process.

Absence plus any `trusted_peers.json`, `audit.jsonl`, `audit-checkpoint.json` or `simulation-checkpoint.json` is `identity_missing`. Corrupt v1 validates before provider: exact schema/private/public, no mutation/no generation. `migrate` always encrypts the original key and self-decrypts/compares candidate before publication. `create` generates only after credentials validate. Missing provider is `identity_credentials_required`; `None` or cancellation is `identity_unlock_cancelled`. Repeated v2 loads do not rewrite.

Define explicit pytest fixtures in `tests/conftest.py`: `credential_provider` maps resolved `request.data_dir` to fresh random ASCII bytes in a per-test closure, returning matching confirmation only for create/migrate; `service_factory` accepts `(data_dir, limits=Limits())`, explicitly passes that provider, and registers created services for finally-close; `legacy_identity_store` writes a valid v1 test fixture and returns its original Identity. No autouse/default monkeypatch of production constructors. Helper fixtures generate no reports/secret repr.

- [ ] Luna updates the existing identity tests to pass the fixture explicitly and adds `test_missing_provider_and_cancel_do_not_create`, `test_migrate_preserves_key_trust_and_audit_bytes`, `test_v1_mismatch_rejected_before_prompt`, `test_history_without_identity_never_regenerates`, `test_v2_wrong_password_and_corruption_preserve_file`, `test_handle_issuer_snapshot_and_single_use`.

```python
assert migrated.public_bytes == old.public_bytes and migrated.fingerprint == old.fingerprint
assert migrated.private_key.sign(b"continuity") == old.private_key.sign(b"continuity")
assert trust.read_bytes() == trust_before and audit.read_bytes() == audit_before
assert checkpoint.read_bytes() == checkpoint_before
assert verify_log(audit, old.public_bytes, checkpoint).valid is True
assert generate_spy.call_count == 0  # migration, bad existing, missing-with-history
assert provider_spy.call_count == 0  # malformed/mismatched v1
assert before == path.read_bytes()  # wrong password, failed migration, repeated successful v2 load
assert not absent_dir.exists()  # absent provider/cancel before storage preparation
assert inspect_identity(data_dir).private_key_verified is False
```

Include failure injection through F1b for serialization/self-check/write/commit outcomes and cancellation before/after KDF/publication. Existing Linux permission tests still assert unchanged bytes for v2 permission tightening, and failed tightening never generates. V1 mismatch metadata diagnostics remains unverified; actual load rejects it.

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_identity.py tests/unit/test_identity_migration.py -q`; expected explicit-credentials/new lifecycle assertions fail.
- [ ] Same Luna implements lifecycle/handle/fixtures only; leave TrustStore unchanged.
- [ ] Controller GREEN: same plus `tests/unit/test_identity_codec.py tests/unit/test_identity_storage.py tests/unit/test_trust.py tests/unit/test_audit.py tests/unit/test_audit_format.py`; expected all pass. Sol reviews identity preservation and private handoff.

## F1d — Service initialization and explicit constructor callers

**Allowed files:** Modify `src/sparc/peer/service.py` initialization only; `tests/integration/conftest.py`, `tests/integration/test_availability.py`, `tests/integration/test_record_pacing.py`, `tests/integration/test_service_listener.py`, `tests/integration/test_service_pairing.py`, `tests/integration/test_service_shutdown.py`, `tests/unit/test_service_audit.py`, `tests/unit/test_service_send.py`, `tests/gui/test_connection_view.py`; create `tests/unit/test_service_identity.py`; controller evidence only in `docs/implementation-status.md`. Simulation calls belong to F1g, GUI-launch fakes to F1e. No other test file may change for constructor adaptation without Sol/controller revising the explicit inventory first.

**Consumes:** F1c public loader and `_consume_unlocked_store`. **Produces:**

```python
class PeerService:
    def __init__(self, data_dir: Path, limits: Limits = Limits(), *,
                 credential_provider: CredentialProvider | None = None,
                 cancelled: CancelPredicate | None = None) -> None: ...
    @classmethod
    def _from_unlocked_store(cls, handle: _UnlockedStore,
                             limits: Limits = Limits(), *,
                             cancelled: CancelPredicate | None = None) -> "PeerService": ...
    def _initialize(self, data_dir: Path, limits: Limits, identity: Identity) -> None: ...
```

Validate limits before loading. Public constructor unlocks then checks cancellation before `_initialize`; private classmethod validates limits, consumes the handle, checks cancellation, allocates via `cls.__new__` and calls `_initialize`. Common initialization starts with current trust/audit/checkpoint code. No provider/password/derived key kept on service. No KDF in handshake/record metrics. Preserve existing initialization failures and close behavior.

- [ ] Luna adds `test_unlock_failure_precedes_all_service_persistence`, `test_unlocked_factory_avoids_second_kdf`, `test_changed_or_reused_handle_cannot_start_service`; updates enumerated callers with explicit fixture/provider kwargs and helper parameters, including reconnect/restart calls sharing the same per-directory fixture secret.

```python
assert trust_constructor.call_count == audit_constructor.call_count == 0
assert socket_constructor.call_count == thread_start.call_count == 0
assert service.own_fingerprint == original.fingerprint
assert kdf_spy.call_count == 1  # unlock + private service factory together
assert not hasattr(service, "credential_provider")
assert reopened.own_fingerprint == before_fingerprint
assert verify_log(audit_path, original.public_bytes).valid is True
```

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_service_identity.py -q`; expected constructor/factory/no-persistence assertions fail.
- [ ] Same Luna implements startup factoring and explicit caller adaptation only.
- [ ] Controller GREEN: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_service_identity.py tests/unit/test_service_audit.py tests/unit/test_service_send.py tests/integration/test_peer_service.py tests/integration/test_availability.py tests/integration/test_record_pacing.py tests/integration/test_service_listener.py tests/integration/test_service_pairing.py tests/integration/test_service_shutdown.py tests/unit/test_handshake.py tests/unit/test_handshake_responder.py tests/unit/test_trust.py -q`; expect pass. Also run `tests/gui/test_connection_view.py` with real Tk display; record skips if no display. Sol checks initialization integration.

## F1e — Responsive masked GUI unlock and private handoff

**Allowed files:** Create `src/sparc/gui/identity_unlock.py`, `tests/unit/test_gui_identity_unlock.py`, `tests/gui/test_identity_unlock.py`; modify `src/sparc/gui/app.py`, `tests/integration/test_gui_cli.py`; controller evidence only in `docs/implementation-status.md`.

**Consumes:** F1c inspection/_unlock_store/credential types, F1d factory. **Produces:** `unlock_identity_for_gui(root: tk.Misc, data_dir: Path) -> _UnlockedStore` in the new module; `launch(data_dir: Path) -> None` keeps its existing external signature.

Use modal masked Toplevel with one/two Entry fields, explicit Unlock/Create/Encrypt identity button, Retry for `identity_unlock_failed`, Cancel/Escape/WM_DELETE_WINDOW. Show existing unverified fingerprint and migration continuity text. Main Tk thread collects/validates UTF-8 input; one worker calls `_unlock_store` with one-use provider and cancel event. Private worker result is never a service event/public queue payload: startup coordination owns a private result slot; UI queue contains outcome code only. Disable submit while work is active; Cancel remains responsive. Poll at 50 ms using `after`; cancel/clear poll IDs and credentials/widgets on every terminal outcome. Library calls finish before worker join/root destruction; no unsafe thread termination. No service constructor runs before successful handle acceptance. `launch` calls the private service factory once, then creates the existing tabs/mainloop.

- [ ] Luna writes `test_gui_cancel_while_kdf_blocked_starts_no_service`, `test_gui_validation_retry_and_safe_error`, `test_gui_close_during_migration_keeps_identity`, `test_gui_worker_handoff_and_setup_cleanup`; update existing fake-launch tests by faking `unlock_identity_for_gui` and `_from_unlocked_store`, preserving tab/close assertions. Real Tk tests assert masks and main-thread Tk calls.

```python
assert entry.cget("show") != ""
assert service_factory.call_count == 0  # blocked KDF then Cancel
assert identity_path.read_bytes() == before  # cancel before publication
assert error.value.code == "identity_unlock_cancelled"
assert worker.is_alive() is False and scheduled_after_ids == []
assert tk_call_thread_ids == {threading.get_ident()}
assert calls.index("unlock_success") < calls.index("service") < calls.index("tabs")
assert calls[-2:] == ["service.close", "root.destroy"]  # later tab setup failure
```

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_gui_identity_unlock.py tests/integration/test_gui_cli.py -q`; expect missing unlock API/startup contract failure.
- [ ] Same Luna implements dialog and app handoff only.
- [ ] Controller GREEN: same plus `tests/gui/test_identity_unlock.py tests/gui/test_app.py tests/gui/test_connection_view.py` with real Tk; expect pass, record actual display skips separately. Sol checks cancellation before/after publication and ordered cleanup.

## F1f — Read-only diagnostics and hidden terminal credentials

**Allowed files:** Create `src/sparc/identity_unlock.py`, `tests/unit/test_identity_console.py`; modify `src/sparc/__main__.py`, `tests/integration/test_check_cli.py`, `tests/integration/test_gui_cli.py`; controller evidence only in `docs/implementation-status.md`.

**Consumes:** F1a/F1c public metadata/types. **Produces:** `console_credentials(request: IdentityUnlockRequest) -> IdentityCredentials | None`; main signature unchanged. Terminal prompts use getpass, encode/validate strict UTF-8, confirm new phrases, no stdin echo fallback. Verify a usable controlling terminal (`/dev/tty` on Linux, console handle on Windows); treat `GetPassWarning` as credentials-required. Ctrl-C/EOF are safe cancellation. Core missing provider never automatically selects this adapter.

`--check` prints exact absence/legacy/encrypted statuses from the spec; encrypted fingerprint label `Public fingerprint (unverified stored metadata): ...`; no key match/decrypt claim. Error status `1`; absent environment diagnostics `0`. GUI `identity_unlock_cancelled` prints `SPARC launch canceled.` to stderr and returns `130`; Tk missing stays `2`. Terminal consumers map cancellation to `130` as well.

- [ ] Luna splits existing subprocess check test into absent and explicitly provisioned encrypted cases, adds legacy/mismatched-public metadata case, corrupt envelope and nonmutation snapshots, guards private-key/KDF/service imports/calls as well as Tk/traffic imports; writes console masked-input/Unicode/confirmation/warning/EOF/Ctrl-C tests.

```python
assert main(["--check", "--data-dir", str(absent_dir)]) == 0
assert not absent_dir.exists()
assert "Public fingerprint: unavailable (identity absent)" in output
assert "Public fingerprint (unverified stored metadata): " + expected_fp in output
assert "encrypted; locked; private key not verified" in output
assert snapshots_after == snapshots_before  # bytes, modes, file listing
assert kdf_spy.call_count == key_loader_spy.call_count == service_spy.call_count == 0
assert captured_credentials.passphrase == text.encode("utf-8")
assert main(gui_cancel_argv) == 130 and "SPARC launch canceled." in stderr
assert "Traceback" not in stderr
```

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/integration/test_check_cli.py tests/unit/test_identity_console.py -q`; expect old check creation/output or missing adapter contract failure.
- [ ] Same Luna implements diagnostics/console adapter and cancellation mapping only.
- [ ] Controller GREEN: same plus `tests/integration/test_gui_cli.py tests/integration/test_analysis_cli.py`; expect pass with no identity unlock in standalone analysis. Sol reviews no accidental mutation/secrets.

## F1g — Simulation private credential exchange and explicit fixture callers

**Allowed files:** Modify `scripts/simulate_peers.py`, `tests/integration/test_simulation.py`; create `tests/unit/test_simulation_credentials.py`; controller evidence only in `docs/implementation-status.md`.

**Consumes:** F1c inspect/provider types, F1d constructor, F1f console adapter. **Produces:**

```python
SimulationCredentialProvider = Callable[[str, IdentityUnlockRequest], IdentityCredentials | None]
def run_simulation(data_root: Path, port_a: int = 0, port_b: int = 0,
                   text: str = "SPARC ✓", *,
                   credential_provider: SimulationCredentialProvider | None = None) -> dict: ...
```

Keep `_child_main(peer_name, data_dir_value, requested_port, expected_text, connection)` signature so existing child wrappers remain valid. Validate inputs before credentials/spawn. Coordinator obtains Alice/Bob credentials sequentially, via public inspections/purpose, before root creation/processes/listeners. Canceled/missing provider raises safe domain error before any creation. For recognized corrupt peer metadata, prepare a public failed-start result rather than treating it as absence or changing its bytes; retain existing incomplete-report cleanup contract. No prompts inside child processes.

After spawning a child, send `canonical` bounded JSON bytes via the existing private `Connection.send_bytes`: exact fields `kind="IDENTITY_CREDENTIALS"`, `passphrase` standard Base64 bytes, `confirmation` Base64 or null. Bound message to 4096 bytes; child polls at existing `_POLL_SECONDS` and receives with `recv_bytes(maxlength=4096)` before service/listener construction, validates exact schema/lengths and uses one-use provider. This is private in-memory IPC, never a report/event or persisted data; Base64 here is transport encoding, not encryption. Parent closes/relinquishes credential references after delivery, child after provider use. Do not call `_report_value`, `_send_message` or generic evidence projection for this message. EOF/deadline yields safe `identity_credentials_required`/startup failure and bounded cleanup. Start the existing 30-second run and startup deadlines after human input finishes; KDF/IPC startup remains inside them.

CLI wraps `console_credentials` with peer-name prompts, passes it explicitly and maps canceled `130`, missing/noninteractive credentials `1`, invalid simulation input existing `2`. Do not add credential CLI flags. Keep report JSON schema and evidence semantics unchanged.

- [ ] Luna adds `test_simulation_requires_provider_before_spawn`, `test_cancel_and_coordinator_eof_leave_no_children`, `test_credential_exchange_is_bounded_and_never_reported`; adapts every existing real `run_simulation`/`load_identity` call in the allowed simulation test file with the explicit stable credential fixture. Retain malformed-Bob incomplete report, repeated-pin reuse, abnormal child exit and deadline/cleanup tests.

```python
assert process_start.call_count == 0 and not data_root.exists()
assert error.value.code == "identity_credentials_required"
assert child_pids_after == child_pids_before and report["cleanup"]["all_children_stopped"]
assert report["complete"] is True and len({p["pid"] for p in report["peers"].values()}) == 2
assert fingerprints_second == fingerprints_first and report_second["pairing"] == []
assert secret_ascii not in json.dumps(report) and secret_base64 not in json.dumps(report)
assert all(p["audit"]["valid"] for p in report["peers"].values())
```

Existing subprocess inert-import assertion stays. Replace its noninteractive successful CLI invocation with a subprocess assertion of credentials-required/no identity/report creation; separately call CLI `main` in-process with patched `console_credentials` generating random in-memory test credentials and assert complete JSON/report writing. No secret subprocess args/env/files/stdin. Console behavior is already covered in F1f.

- [ ] Controller RED: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_simulation_credentials.py -q`; expect provider/no-spawn/IPC contract failure.
- [ ] Same Luna implements simulation integration and enumerated tests only.
- [ ] Controller GREEN: `/home/harsh/SPARC/.venv/bin/python -m pytest tests/unit/test_simulation_credentials.py tests/integration/test_simulation.py -q`; expect pass, two actual spawn peers, finite cleanup and unchanged report schema. Sol reviews secret transport and failure projection.

## F1h — Milestone verification, platform evidence and final commit gate

**Allowed files:** Controller-only updates `docs/implementation-status.md`, `CHANGELOG.md`; create `docs/f1-identity-at-rest-evidence.md`; Sol review is read-only. No production/test edits in this unit: discoveries return to their owning lettered unit for another RED/GREEN/review cycle.

- [ ] Controller records the actual Linux full-suite command `/home/harsh/SPARC/.venv/bin/python -m pytest -q`, exit status/pass/fail/skip counts and duration. Do not broaden tests after an already recorded final unchanged run unless a failure or new change requires it.
- [ ] Controller runs actual Tk startup smoke on Linux with a dedicated temporary directory: masked create/confirm, existing unlock, wrong phrase Retry, Cancel during blocked startup test, and legacy migration. Record public fingerprint continuity and cleanup; no secret screenshots/terminal recordings. Existing GUI suite skips must not be labeled passes.
- [ ] Controller runs on real Windows NTFS using a supported pinned-library interpreter: `python -m pytest tests/integration/test_identity_windows.py tests/unit/test_identity_codec.py tests/unit/test_identity_migration.py tests/unit/test_identity_console.py tests/integration/test_check_cli.py tests/integration/test_simulation.py tests/gui/test_identity_unlock.py -q`. Record Python/cryptography/OpenSSL versions, ACL/locking/reparse/file-replace behavior, terminal restoration, GUI cancellation and same-key migration. Run `python -m pytest -q` on Windows after these pass; actual output is required. If no Windows runner/display is available, mark these pending, keep F1 pending, and report Linux verification separately without Windows/release claims.
- [ ] Controller measures one actual production-profile Argon2id derivation on each platform using a fresh in-memory random passphrase/salt, reporting elapsed time only. Confirm 65536 KiB/three passes/four lanes and usable startup. No alternate profile, secret output or analysis timing modification. Missing platform evidence remains pending.
- [ ] Sol performs independent read-only milestone security/integration review against the approved spec and plan: candidate authentication, bounds before KDF, no secret alongside ciphertext, exact key/fingerprint migration, no failed-operation generation, pre/postcommit outcomes, OS ownership/ACL/no-follow/lock behavior, public check honesty, cancellation, service/trust/audit/handshake continuity and simulation secret suppression. Findings are fixed in owning units before reevaluation.
- [ ] Controller verifies scope with `git diff --check` and `git status --short`; reviews evidence and changed-file inventory; updates F1 row/checklist only when all required gates actually passed. Note any unavailable Windows evidence explicitly and leave F1 pending rather than fabricating completion. T1 cannot start while pending.
- [ ] Only after milestone gates pass, controller stages exactly the F1 files from this plan and commits `feat: encrypt persistent identity keys at rest`; records the resulting ref and actual verification evidence. No whole-tree staging. The commit command is conditional on passed gates and user-approved execution, not authorized by this planning document.

## Plan self-review and handoff

Coverage: F1a format/KDF/types; F1b OS storage/atomicity/races; F1c credentials/migration/diagnostics API/handle; F1d service/audit/trust/handshake callers; F1e Tk unlock/cancel; F1f public CLI/terminal behavior; F1g simulation; F1h actual platform evidence/security review/commit. Review Focus items map to named tests above. All interfaces, bounds, outcomes and constructor adaptation files are fixed; no pending implementation choice changes the security contract.

The repository/worktree contain no applicable `AGENTS.md`; the discovered `/home/harsh/.codex/AGENTS.md` is empty. No product tests or platform checks were run while writing this plan, and none of its expected PASS results are evidence. Review this written plan before execution; preserve Sol design/review, the reused Luna tests/implementation, and controller-run RED/GREEN/commit roles.
