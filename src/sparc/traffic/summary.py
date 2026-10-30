"""Read-only, bounded summaries of completed SQLite traffic indexes."""

from __future__ import annotations

from decimal import Decimal, localcontext, ROUND_HALF_EVEN
import json
import math
from pathlib import Path
import re
import sqlite3
import stat

from sparc.models import SparcError

from .models import ConversionResult, TrafficReport


_BATCH = 500
_LIMIT = 100
_ERROR = "Could not summarize the completed traffic index"
_BINS = ((0, 63, "0-63"), (64, 127, "64-127"), (128, 511, "128-511"),
         (512, 1023, "512-1023"), (1024, 1518, "1024-1518"), (1519, None, "1519+"))
_REQUIRED = {
    "source_name", "source_sha256", "source_bytes", "display_filter", "versions",
    "evidence_type", "definitions", "schema_version", "packet_count", "complete",
}


def _fail(cause=None):
    error = SparcError("traffic_summary_failed", _ERROR)
    if cause is None:
        raise error
    raise error from cause


def _integer(value, *, nullable=False, minimum=None, maximum=None):
    if value is None and nullable:
        return None
    if type(value) is not int:
        _fail()
    if minimum is not None and value < minimum or maximum is not None and value > maximum:
        _fail()
    return value


def _text(value, *, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        _fail()
    return value


def _decimal(value):
    if not isinstance(value, str):
        _fail()
    try:
        parsed = Decimal(value)
    except Exception as error:
        _fail(error)
    if not parsed.is_finite():
        _fail()
    return parsed


def _exact_difference(later: Decimal, earlier: Decimal) -> Decimal:
    lsign, ldigits, lexp = later.as_tuple()
    esign, edigits, eexp = earlier.as_tuple()
    exponent = min(lexp, eexp)
    left = int("".join(map(str, ldigits)) or "0") * (10 ** (lexp - exponent))
    right = int("".join(map(str, edigits)) or "0") * (10 ** (eexp - exponent))
    if lsign:
        left = -left
    if esign:
        right = -right
    difference = left - right
    digits = tuple(map(int, str(abs(difference)))) if difference else (0,)
    return Decimal((1 if difference < 0 else 0, digits, exponent))


def _json_metadata(connection):
    values = {}
    cursor = connection.execute("SELECT key, value FROM metadata ORDER BY key")
    while True:
        batch = cursor.fetchmany(_BATCH)
        if not batch:
            break
        for key, text in batch:
            if not isinstance(key, str) or not isinstance(text, str):
                _fail()
            try:
                values[key] = json.loads(text)
            except (ValueError, TypeError) as error:
                _fail(error)
    return values


def _endpoint_sort(values):
    return tuple((0, "") if value is None else (1, value) for value in values)


def _top_insert(top, item, key):
    if len(top) < _LIMIT:
        top.append(item)
        return
    worst = max(range(len(top)), key=lambda position: key(top[position]))
    if key(item) < key(top[worst]):
        top[worst] = item


def _directional(connection):
    cursor = connection.execute(
        "SELECT src, dst, src_port, dst_port, captured_length FROM packets "
        "ORDER BY src COLLATE BINARY, dst COLLATE BINARY, src_port, dst_port"
    )
    top = []
    total_groups = 0
    current = object()
    count = byte_count = 0
    key_values = None

    def flush():
        nonlocal total_groups
        if key_values is None:
            return
        total_groups += 1
        item = {"src": key_values[0], "dst": key_values[1], "src_port": key_values[2],
                "dst_port": key_values[3], "packet_count": count, "captured_bytes": byte_count}
        _top_insert(top, item, lambda row: (-row["captured_bytes"], _endpoint_sort(
            (row["src"], row["dst"], row["src_port"], row["dst_port"]))))

    while True:
        batch = cursor.fetchmany(_BATCH)
        if not batch:
            break
        for src, dst, sport, dport, length in batch:
            group = (src, dst, sport, dport)
            if group != current:
                flush()
                current = group
                key_values = group
                count = byte_count = 0
            count += 1
            byte_count += length
    flush()
    top.sort(key=lambda row: (-row["captured_bytes"], _endpoint_sort(
        (row["src"], row["dst"], row["src_port"], row["dst_port"]))))
    return top, total_groups


def _tcp(connection):
    cursor = connection.execute(
        "SELECT tcp_stream, number, src, dst, src_port, dst_port, captured_length "
        "FROM packets WHERE tcp_stream IS NOT NULL ORDER BY tcp_stream, number"
    )
    top = []
    total_groups = 0
    current = object()
    count = byte_count = 0
    first = None
    stream = None

    def flush():
        nonlocal total_groups
        if first is None:
            return
        total_groups += 1
        item = {"tcp_stream": stream, "src": first[0], "dst": first[1],
                "src_port": first[2], "dst_port": first[3], "packet_count": count,
                "captured_bytes": byte_count}
        _top_insert(top, item, lambda row: (-row["captured_bytes"], row["tcp_stream"]))

    while True:
        batch = cursor.fetchmany(_BATCH)
        if not batch:
            break
        for stream_id, _number, src, dst, sport, dport, length in batch:
            if stream_id != current:
                flush()
                current = stream = stream_id
                first = (src, dst, sport, dport)
                count = byte_count = 0
            count += 1
            byte_count += length
    flush()
    top.sort(key=lambda row: (-row["captured_bytes"], row["tcp_stream"]))
    return top, total_groups


def _conversion(metadata, path, actual_count):
    source_bytes = metadata["source_bytes"]
    versions = metadata["versions"]
    if type(source_bytes) is not int or source_bytes < 0 or not isinstance(versions, dict):
        _fail()
    try:
        output_bytes = path.stat().st_size
    except OSError as error:
        _fail(error)
    checkpoint = metadata.get("conversion")
    if checkpoint is None:
        elapsed = 0
        rate = None
        conversion_metadata = {"measurement_scope": "not_measured"}
    else:
        if (not isinstance(checkpoint, dict) or checkpoint.get("complete") is not True
                or type(checkpoint.get("packet_count")) is not int
                or checkpoint.get("packet_count") != actual_count
                or type(checkpoint.get("elapsed_ns")) is not int
                or checkpoint["elapsed_ns"] < 0
                or type(checkpoint.get("source_bytes")) is not int
                or checkpoint["source_bytes"] != source_bytes
                or checkpoint.get("measurement_scope") != "import_prepublication_checkpoint"):
            _fail()
        elapsed = checkpoint["elapsed_ns"]
        rate = checkpoint.get("packets_s")
        if rate is not None and (isinstance(rate, bool) or not isinstance(rate, (int, float))
                                 or not math.isfinite(rate) or rate < 0):
            _fail()
        if isinstance(rate, int):
            rate = float(rate)
        conversion_metadata = dict(checkpoint)
    return ConversionResult(True, actual_count, elapsed, source_bytes, output_bytes,
                            rate, dict(versions), conversion_metadata)


def summarize_database(database: Path) -> TrafficReport:
    """Summarize an existing completed index using bounded read-only queries."""
    path = Path(database)
    connection = None
    try:
        resolved = path.resolve(strict=True)
        if not stat.S_ISREG(resolved.stat().st_mode):
            _fail()
        uri = resolved.as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA cache_size=-2048")
        metadata = _json_metadata(connection)
        if not _REQUIRED <= metadata.keys() or metadata["schema_version"] != 1 or metadata["complete"] is not True:
            _fail()
        if (type(metadata["schema_version"]) is not int or type(metadata["packet_count"]) is not int
                or metadata["packet_count"] < 0
                or not isinstance(metadata["source_name"], str) or not metadata["source_name"]
                or Path(metadata["source_name"]).name != metadata["source_name"]
                or not isinstance(metadata["source_sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", metadata["source_sha256"], re.ASCII) is None
                or type(metadata["source_bytes"]) is not int or metadata["source_bytes"] < 0
                or (metadata["display_filter"] is not None and not isinstance(metadata["display_filter"], str))
                or not isinstance(metadata["versions"], dict)
                or not isinstance(metadata["definitions"], dict)
                or metadata["evidence_type"] not in {"synthetic_fixture", "simulation", "physical_device", "unspecified"}):
            _fail()
        for name in ("python", "pyshark", "tshark"):
            if name not in metadata["versions"] or (metadata["versions"][name] is not None
                                                        and not isinstance(metadata["versions"][name], str)):
                _fail()
        definitions = metadata["definitions"]
        if any(name not in definitions or not isinstance(definitions[name], str) or not definitions[name]
               for name in ("index", "timestamps", "captured_bytes_s", "retransmissions")):
            _fail()

        actual_count = connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        if type(actual_count) is not int or metadata["packet_count"] != actual_count:
            _fail()
        bins = {label: 0 for _low, _high, label in _BINS}
        from .rates import CaptureRateBins
        capture_bins=CaptureRateBins()
        packet_count = total_bytes = retransmissions = 0
        first_timestamp = last_timestamp = None
        cursor = connection.execute(
            "SELECT number, timestamp, captured_length, wire_length, highest_protocol, src, dst, "
            "src_port, dst_port, tcp_stream, tcp_flags, retransmission FROM packets ORDER BY number ASC"
        )
        while True:
            batch = cursor.fetchmany(_BATCH)
            if not batch:
                break
            for record in batch:
                number, timestamp, length, wire, protocol, src, dst, sport, dport, stream, flags, retrans = record
                _integer(number, minimum=0)
                parsed_timestamp = _decimal(timestamp)
                _integer(length, minimum=0)
                _integer(wire, minimum=0)
                _text(protocol)
                _text(src, nullable=True); _text(dst, nullable=True); _text(flags, nullable=True)
                _integer(sport, nullable=True, minimum=0, maximum=65535)
                _integer(dport, nullable=True, minimum=0, maximum=65535)
                _integer(stream, nullable=True, minimum=0)
                if retrans is not None and (type(retrans) is not int or retrans not in (0, 1)):
                    _fail()
                if first_timestamp is None:
                    first_timestamp = parsed_timestamp
                last_timestamp = parsed_timestamp
                packet_count += 1
                total_bytes += length
                capture_bins.add(parsed_timestamp,length)
                if retrans == 1:
                    retransmissions += 1
                for low, high, label in _BINS:
                    if length >= low and (high is None or length <= high):
                        bins[label] += 1
                        break
        if packet_count != actual_count:
            _fail()
        if packet_count < 2:
            duration = rate = None
        else:
            duration = _exact_difference(last_timestamp, first_timestamp)
            if duration > 0:
                with localcontext() as context:
                    context.prec = 50
                    context.rounding = ROUND_HALF_EVEN
                    rate = Decimal(total_bytes) / duration
            else:
                rate = None

        protocols_cursor = connection.execute(
            "SELECT highest_protocol, COUNT(*) AS n FROM packets GROUP BY highest_protocol "
            "ORDER BY n DESC, highest_protocol COLLATE BINARY ASC"
        )
        protocol_counts = {}
        protocol_total = 0
        while True:
            batch = protocols_cursor.fetchmany(_BATCH)
            if not batch:
                break
            protocol_total += len(batch)
            for protocol, count in batch:
                if len(protocol_counts) < _LIMIT:
                    protocol_counts[protocol] = count
        directional, directional_total = _directional(connection)
        conversations, conversation_total = _tcp(connection)
        metadata = dict(metadata)
        metadata.update({
            'capture_rate_bins':capture_bins.finish(),
            "presentation_limit": _LIMIT,
            "group_totals": {"protocol_counts": protocol_total, "directional_bytes": directional_total,
                             "tcp_conversations": conversation_total},
            "truncated": {"protocol_counts": protocol_total > _LIMIT,
                          "directional_bytes": directional_total > _LIMIT,
                          "tcp_conversations": conversation_total > _LIMIT},
            "definitions": {
                **definitions,
                "protocol_ordering": "count descending, binary protocol text ascending",
                "directional_grouping": "ordered source/destination address and port tuple; NULL is preserved",
                "tcp_endpoint_selection": "first included packet by packet number; both directions are grouped",
                "rate_precision": "Decimal precision 50 with ROUND_HALF_EVEN; no float conversion",
                "unavailable_intervals": "duration and captured bytes per second are unavailable below two packets; rate is also unavailable for nonpositive duration",
            },
        })
        conversion = _conversion(metadata, resolved, actual_count)
        return TrafficReport(metadata, packet_count, total_bytes, duration, rate, protocol_counts,
                             directional, conversations, bins, retransmissions, conversion)
    except SparcError as error:
        if error.code == "traffic_summary_failed" and error.message == _ERROR:
            raise
        _fail(error)
    except Exception as error:
        _fail(error)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception as error:
                _fail(error)
