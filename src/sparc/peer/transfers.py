"""Bounded per-session image transfer state and streaming file ownership.

Record callbacks never wait for disk I/O. One sender and one receiver worker
own their handles; a condition protects state and a small queue feeds disk work.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import queue
import secrets
import stat
import tempfile
import threading
import time

from ..images import inspect_image
from ..models import ServiceEvent, SparcError
from ..protocol.files import CHUNK_BYTES, MAX_FILE_BYTES, validate_file

OFFER_TIMEOUT = 120.0
ACK_TIMEOUT = 10.0
_TERMINAL = {'verified', 'rejected', 'canceled', 'failed', 'unconfirmed'}


@dataclass
class _Transfer:
    transfer_id: str
    origin: str
    filename: str
    status: str
    path: Path | None = None
    size: int = 0
    sha256: str = ''
    media_type: str = ''
    bytes_done: int = 0
    changed: float = field(default_factory=time.monotonic)
    stop: threading.Event = field(default_factory=threading.Event)
    inbox: queue.Queue = field(default_factory=lambda: queue.Queue(6))
    pending: dict = field(default_factory=dict)
    result: tuple | None = None
    inspection: object = None
    started_ns: int = 0
    written_ns: int = 0
    elapsed_ns: int = 0
    hash_ns: int = 0
    published: bool = False
    emitted_at: float = 0


class TransferManager:
    """Image-only coordinator owned by exactly one authenticated session."""

    def __init__(self, session, emit, audit, peer_fingerprint):
        self.session = session
        self.emit = emit
        self.audit = audit
        self.peer_fingerprint = peer_fingerprint
        self._condition = threading.Condition(threading.RLock())
        self._closed = False
        self._outgoing: _Transfer | None = None
        self._incoming: _Transfer | None = None
        self._workers: set[threading.Thread] = set()
        self._recent: OrderedDict[str, float] = OrderedDict()

    def _check(self, transfer):
        if self._closed or transfer.stop.is_set():
            raise SparcError('operation_cancelled', 'Image transfer was canceled')

    def _notify(self, transfer, *, progress=False, reason=''):
        with self._condition:
            now = time.monotonic()
            if progress and now-transfer.emitted_at < .1:
                return
            transfer.emitted_at = now
            data = dict(transfer_id=transfer.transfer_id, origin=transfer.origin,
                        filename=transfer.filename, size=transfer.size, sha256=transfer.sha256,
                        media_type=transfer.media_type, status=transfer.status,
                        bytes_done=transfer.bytes_done, peer_fingerprint=self.peer_fingerprint,
                        inspection=transfer.inspection, reason=reason,
                        path=str(transfer.path) if transfer.path else None,
                        elapsed_ns=transfer.elapsed_ns, hash_ns=transfer.hash_ns,
                        goodput_bytes_s=(transfer.size*1e9/transfer.elapsed_ns
                                         if transfer.status=='verified' and transfer.elapsed_ns else None))
        self.emit(ServiceEvent('image_transfer', data))

    def _remember(self, tid):
        self._recent[tid] = time.monotonic()
        self._recent.move_to_end(tid)
        while len(self._recent)>128:
            self._recent.popitem(last=False)

    def _finish(self, transfer, status, reason=''):
        with self._condition:
            if transfer.status in _TERMINAL:
                return
            transfer.status = status
            transfer.stop.set()
            self._remember(transfer.transfer_id)
            self._condition.notify_all()
        self._notify(transfer, reason=reason)

    def _enqueue(self, payload, *, bulk=False, transfer=None, wait=True):
        end = time.monotonic()+ACK_TIMEOUT
        while True:
            if transfer is not None:
                self._check(transfer)
            try:
                if bulk:
                    self.session.enqueue_bulk(payload)
                else:
                    send = getattr(self.session, 'enqueue_transfer_control', None)
                    if send:
                        send(payload)
                    else:
                        self.session.enqueue(payload, control=True)
                return
            except SparcError as exc:
                if exc.code!='busy' or not wait or time.monotonic()>=end:
                    raise
                with self._condition:
                    self._condition.wait(.01)

    def _cancel_wire(self, transfer, reason):
        try:
            self._enqueue(dict(kind='file_cancel', transfer_id=transfer.transfer_id,
                               reason=reason[:120] or 'canceled'), wait=False)
        except (SparcError, OSError):
            pass

    def _fail(self, transfer, error):
        code = getattr(error, 'code', 'image_storage_failed')
        status = 'unconfirmed' if transfer.published or transfer.status=='waiting_result' else 'failed'
        if code=='operation_cancelled':
            status = 'unconfirmed' if transfer.published else 'canceled'
        self._finish(transfer, status, f'Image transfer stopped: {code}')
        self._cancel_wire(transfer, code)
        if code in {'image_integrity_failed','audit_storage_failed'}:
            self.session._terminate(SparcError(code, 'Image verification or durable audit failed'))

    def _start(self, target, transfer):
        def run():
            try:
                target(transfer)
            except Exception as exc:
                self._fail(transfer, exc)
            finally:
                with self._condition:
                    if self._outgoing is transfer:
                        self._outgoing = None
                    if self._incoming is transfer:
                        self._incoming = None
                    self._workers.discard(threading.current_thread())
                    self._condition.notify_all()
        worker = threading.Thread(target=run, name=f'sparc-image-{transfer.origin}', daemon=True)
        with self._condition:
            self._workers.add(worker)
        worker.start()

    def send_image(self, path) -> str:
        path = Path(path).absolute()
        with self._condition:
            if self._closed:
                raise SparcError('operation_cancelled','Session has closed')
            if self._outgoing is not None:
                raise SparcError('busy','An outgoing image is already active')
            transfer = _Transfer(secrets.token_hex(16), 'outgoing', path.name, 'preparing', path)
            self._outgoing = transfer
        self._notify(transfer)
        self._start(self._send_file, transfer)
        return transfer.transfer_id

    def respond(self, transfer_id, destination: Path | None):
        with self._condition:
            transfer = self._incoming
            if self._closed or transfer is None or transfer.transfer_id!=transfer_id or transfer.status!='offered':
                raise SparcError('invalid_transfer','Image offer is no longer awaiting acceptance')
            if time.monotonic()-transfer.changed >= OFFER_TIMEOUT:
                raise SparcError('image_timeout','Image offer expired')
            if destination is None:
                self._finish(transfer, 'rejected')
                self._incoming = None
                self._enqueue(dict(kind='file_decision',transfer_id=transfer_id,
                                   decision='reject',reason='rejected'),wait=False)
                return
            path = Path(destination).absolute()
            if os.path.lexists(path) or not path.parent.is_dir():
                raise SparcError('image_destination_exists','Choose a new filename in an existing folder')
            transfer.path = path
            transfer.status = 'accepting'
        self._start(self._receive_file, transfer)

    def cancel(self, transfer_id):
        with self._condition:
            transfer = next((t for t in (self._outgoing,self._incoming)
                             if t is not None and t.transfer_id==transfer_id), None)
            if transfer is None or transfer.status in _TERMINAL:
                return
            self._finish(transfer,'unconfirmed' if transfer.published else 'canceled')
            if transfer is self._incoming and not any(t.name=='sparc-image-incoming' for t in self._workers):
                self._incoming = None
        self._cancel_wire(transfer,'canceled')

    def handle(self, record, evidence):
        payload = record.payload
        tid = payload['transfer_id']
        kind = payload['kind']
        with self._condition:
            if self._closed:
                return
            self._expire_recent()
            if tid in self._recent:
                return
            if kind=='file_offer':
                if any(t is not None and t.transfer_id==tid for t in (self._incoming,self._outgoing)):
                    raise SparcError('invalid_transfer','Duplicate image transfer ID')
                if self._incoming is not None:
                    self._remember(tid)
                    self._enqueue(dict(kind='file_decision',transfer_id=tid,decision='reject',reason='busy'),wait=False)
                    return
                transfer = _Transfer(tid,'incoming',payload['filename'],'offered',size=payload['size'],
                                     sha256=payload['sha256'],media_type=payload['media_type'])
                self._incoming = transfer
                self._notify(transfer)
                return
            if kind=='file_cancel':
                transfer = next((t for t in (self._incoming,self._outgoing)
                                 if t is not None and t.transfer_id==tid), None)
            elif kind in {'file_decision','file_chunk_ack','file_result'}:
                transfer = self._outgoing
            else:
                transfer = self._incoming
            if transfer is None or transfer.transfer_id!=tid:
                raise SparcError('invalid_transfer','Unexpected image transfer ID or direction')
            self._check(transfer)
            if kind=='file_cancel':
                self._finish(transfer,'unconfirmed' if transfer.published else 'canceled',payload['reason'])
                if transfer is self._incoming and transfer.path is None:
                    self._incoming = None
            elif kind=='file_decision':
                if transfer.status!='offered':
                    raise SparcError('invalid_transfer','Unexpected image decision')
                if payload['decision']=='reject':
                    self._finish(transfer,'rejected',payload['reason'])
                else:
                    transfer.status = 'accepted'
                    self._condition.notify_all()
            elif kind=='file_chunk_ack':
                pending = transfer.pending.get(payload['index'])
                if transfer.status!='transferring' or pending is None or pending[0]!=payload['sha256']:
                    raise SparcError('image_integrity_failed','Unexpected image chunk acknowledgment')
                del transfer.pending[payload['index']]
                transfer.bytes_done += pending[2]
                self._condition.notify_all()
                self._notify(transfer,progress=True)
            elif kind=='file_result':
                if transfer.status!='waiting_result' or transfer.result is not None:
                    raise SparcError('invalid_transfer','Unexpected image result')
                self._match_complete(transfer,payload)
                transfer.result = (payload,evidence)
                self._condition.notify_all()
            elif kind in {'file_chunk','file_complete'}:
                if transfer.status not in {'accepted','transferring'}:
                    raise SparcError('invalid_transfer','Image data arrived before acceptance')
                try:
                    transfer.inbox.put_nowait((record,evidence))
                except queue.Full as exc:
                    raise SparcError('image_integrity_failed','Image exceeded its receive window') from exc

    def written(self, payload, protected):
        if payload['kind']!='file_chunk':
            return
        with self._condition:
            transfer = self._outgoing
            if self._closed or transfer is None or transfer.transfer_id!=payload['transfer_id'] or transfer.stop.is_set():
                return
            if not transfer.written_ns:
                transfer.written_ns = time.perf_counter_ns()
            transfer.inspection = protected.inspection
            self._notify(transfer,progress=True)

    def _wait(self, transfer, predicate, deadline):
        with self._condition:
            while not predicate():
                self._check(transfer)
                remaining = deadline()-time.monotonic()
                if remaining<=0:
                    raise SparcError('image_timeout','Image response deadline expired')
                self._condition.wait(min(.1,remaining))
            self._check(transfer)

    def _send_file(self, transfer):
        flags = os.O_RDONLY | getattr(os,'O_NOFOLLOW',0)
        fd = os.open(transfer.path,flags)
        with os.fdopen(fd,'rb') as source:
            info_stat = os.fstat(source.fileno())
            if not stat.S_ISREG(info_stat.st_mode) or not 0<info_stat.st_size<=MAX_FILE_BYTES:
                raise SparcError('invalid_image','Choose a regular image file up to 100 MiB')
            self._check(transfer)
            info = inspect_image(source)
            digest = hashlib.sha256()
            started = time.perf_counter_ns()
            count = 0
            while True:
                self._check(transfer)
                data = source.read(CHUNK_BYTES)
                if not data:
                    break
                count += len(data)
                if count>MAX_FILE_BYTES:
                    raise SparcError('invalid_image','Image exceeds 100 MiB')
                digest.update(data)
            if count!=info_stat.st_size:
                raise SparcError('image_source_changed','Image changed while hashing')
            transfer.hash_ns = time.perf_counter_ns()-started
            transfer.size = count
            transfer.sha256 = digest.hexdigest()
            transfer.media_type = info.media_type
            offer = dict(kind='file_offer',transfer_id=transfer.transfer_id,filename=transfer.filename,
                         size=count,sha256=transfer.sha256,media_type=info.media_type,chunk_size=CHUNK_BYTES)
            validate_file(offer)
            source.seek(0)
            with self._condition:
                self._check(transfer)
                transfer.status = 'offered'
                transfer.changed = time.monotonic()
            self._notify(transfer)
            self._enqueue(offer,transfer=transfer)
            self._wait(transfer,lambda:transfer.status!='offered',lambda:transfer.changed+OFFER_TIMEOUT)
            with self._condition:
                transfer.status = 'transferring'
                transfer.started_ns = time.perf_counter_ns()
            self._notify(transfer)
            streamed = hashlib.sha256()
            for index,offset in enumerate(range(0,transfer.size,CHUNK_BYTES)):
                self._wait(transfer,lambda:len(transfer.pending)<4,
                           lambda:min((x[1]+ACK_TIMEOUT for x in transfer.pending.values()),default=time.monotonic()+ACK_TIMEOUT))
                data = source.read(min(CHUNK_BYTES,transfer.size-offset))
                if len(data)!=min(CHUNK_BYTES,transfer.size-offset):
                    raise SparcError('image_source_changed','Image changed while sending')
                streamed.update(data)
                chunk_hash = hashlib.sha256(data).hexdigest()
                with self._condition:
                    transfer.pending[index] = (chunk_hash,time.monotonic(),len(data))
                self._enqueue(dict(kind='file_chunk',transfer_id=transfer.transfer_id,index=index,offset=offset,
                                   byte_count=len(data),sha256=chunk_hash,data=base64.b64encode(data).decode('ascii')),
                              bulk=True,transfer=transfer)
            if source.read(1) or streamed.hexdigest()!=transfer.sha256:
                raise SparcError('image_source_changed','Image changed while sending')
            self._wait(transfer,lambda:not transfer.pending,
                       lambda:min((x[1]+ACK_TIMEOUT for x in transfer.pending.values()),default=time.monotonic()+ACK_TIMEOUT))
            with self._condition:
                transfer.status = 'waiting_result'
                transfer.changed = time.monotonic()
            self._notify(transfer)
            self._enqueue(dict(kind='file_complete',transfer_id=transfer.transfer_id,size=transfer.size,
                               sha256=transfer.sha256),transfer=transfer)
            self._wait(transfer,lambda:transfer.result is not None,lambda:transfer.changed+ACK_TIMEOUT)
            self._check(transfer)
            payload,evidence = transfer.result
            self.audit('image_delivered',dict(transfer_id=transfer.transfer_id,size=transfer.size,
                                             sha256=transfer.sha256,peer_evidence=evidence))
            self._check(transfer)
            transfer.elapsed_ns = time.perf_counter_ns()-(transfer.written_ns or transfer.started_ns)
            self._finish(transfer,'verified')

    @staticmethod
    def _match_complete(transfer,payload):
        if payload['size']!=transfer.size or payload['sha256']!=transfer.sha256:
            raise SparcError('image_integrity_failed','Image completion size or digest does not match')

    def _receive_file(self, transfer):
        temporary = None
        try:
            fd,name = tempfile.mkstemp(prefix='.sparc-image-',dir=transfer.path.parent)
            temporary = Path(name)
            with os.fdopen(fd,'w+b') as destination:
                with self._condition:
                    self._check(transfer)
                    transfer.status = 'accepted'
                    transfer.changed = time.monotonic()
                    transfer.started_ns = time.perf_counter_ns()
                self._notify(transfer)
                self._enqueue(dict(kind='file_decision',transfer_id=transfer.transfer_id,
                                   decision='accept',reason='accepted'),transfer=transfer)
                digest = hashlib.sha256()
                index = 0
                while True:
                    self._check(transfer)
                    try:
                        record,evidence = transfer.inbox.get(timeout=.05)
                    except queue.Empty:
                        if time.monotonic()-transfer.changed>=ACK_TIMEOUT:
                            raise SparcError('image_timeout','Image chunk deadline expired')
                        continue
                    payload = record.payload
                    if payload['kind']=='file_complete':
                        self._match_complete(transfer,payload)
                        if transfer.bytes_done!=transfer.size or digest.hexdigest()!=transfer.sha256:
                            raise SparcError('image_integrity_failed','Received image size or digest does not match')
                        destination.flush()
                        info = inspect_image(destination)
                        if info.media_type!=transfer.media_type:
                            raise SparcError('image_integrity_failed','Image format differs from offer')
                        os.fsync(destination.fileno())
                        with self._condition:
                            self._check(transfer)
                            # link() is atomic and fails for any pre-existing destination, including symlinks.
                            os.link(temporary,transfer.path)
                            transfer.published = True
                        temporary.unlink()
                        temporary = None
                        self._sync_directory(transfer.path.parent)
                        self._check(transfer)
                        self.audit('image_received',dict(transfer_id=transfer.transfer_id,size=transfer.size,
                                                       sha256=transfer.sha256,peer_evidence=evidence))
                        self._check(transfer)
                        self._enqueue(dict(kind='file_result',transfer_id=transfer.transfer_id,size=transfer.size,
                                           sha256=transfer.sha256,status='verified'),transfer=transfer)
                        transfer.elapsed_ns = time.perf_counter_ns()-transfer.started_ns
                        self._finish(transfer,'verified')
                        return
                    data = base64.b64decode(payload['data'],validate=True)
                    if (payload['index']!=index or payload['offset']!=transfer.bytes_done or
                            len(data)!=min(CHUNK_BYTES,transfer.size-transfer.bytes_done) or
                            len(data)!=payload['byte_count'] or hashlib.sha256(data).hexdigest()!=payload['sha256']):
                        raise SparcError('image_integrity_failed','Image chunk order, length or digest is invalid')
                    self._check(transfer)
                    destination.write(data)
                    digest.update(data)
                    transfer.bytes_done += len(data)
                    transfer.inspection = record.inspection
                    transfer.status = 'transferring'
                    transfer.changed = time.monotonic()
                    index += 1
                    self._enqueue(dict(kind='file_chunk_ack',transfer_id=transfer.transfer_id,index=payload['index'],
                                       sha256=payload['sha256'],status='stored'),transfer=transfer)
                    self._notify(transfer,progress=True)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _sync_directory(path):
        fd = os.open(path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _expire_recent(self):
        now = time.monotonic()
        while self._recent and now-next(iter(self._recent.values()))>=30:
            self._recent.popitem(last=False)

    def poll(self):
        with self._condition:
            self._expire_recent()
            incoming = self._incoming
            expired = incoming is not None and incoming.status=='offered' and time.monotonic()-incoming.changed>=OFFER_TIMEOUT
        if expired:
            self.cancel(incoming.transfer_id)

    def close(self):
        with self._condition:
            self._closed = True
            for transfer in (self._incoming,self._outgoing):
                if transfer is not None:
                    self._finish(transfer,'unconfirmed' if transfer.published or transfer.origin=='outgoing' else 'canceled',
                                 'Connection closed before confirmation')
            self._condition.notify_all()

    def join(self, timeout=2):
        end = time.monotonic()+max(0,timeout)
        with self._condition:
            workers = list(self._workers)
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(max(0,end-time.monotonic()))
        return all(not w.is_alive() or w is threading.current_thread() for w in workers)
