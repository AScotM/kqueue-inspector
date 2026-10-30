#!/usr/bin/env python3

import argparse
import collections
import contextlib
import csv
import dataclasses
import datetime
import errno
import fnmatch
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import platform
import queue
import re
import resource
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import typing
import uuid

APP_NAME = "kqueue-forensics"
APP_VERSION = "1.0.0"
SCHEMA_VERSION = 1

FILTER_NAMES = {
    "read": "KQ_FILTER_READ",
    "write": "KQ_FILTER_WRITE",
    "vnode": "KQ_FILTER_VNODE",
    "proc": "KQ_FILTER_PROC",
    "signal": "KQ_FILTER_SIGNAL",
    "timer": "KQ_FILTER_TIMER",
    "user": "KQ_FILTER_USER",
}

FLAG_NAMES = {
    "add": "KQ_EV_ADD",
    "delete": "KQ_EV_DELETE",
    "enable": "KQ_EV_ENABLE",
    "disable": "KQ_EV_DISABLE",
    "oneshot": "KQ_EV_ONESHOT",
    "clear": "KQ_EV_CLEAR",
    "receipt": "KQ_EV_RECEIPT",
    "dispatch": "KQ_EV_DISPATCH",
    "eof": "KQ_EV_EOF",
    "error": "KQ_EV_ERROR",
}

NOTE_NAMES = {
    "delete": "KQ_NOTE_DELETE",
    "write": "KQ_NOTE_WRITE",
    "extend": "KQ_NOTE_EXTEND",
    "attrib": "KQ_NOTE_ATTRIB",
    "link": "KQ_NOTE_LINK",
    "rename": "KQ_NOTE_RENAME",
    "revoke": "KQ_NOTE_REVOKE",
    "exit": "KQ_NOTE_EXIT",
    "fork": "KQ_NOTE_FORK",
    "exec": "KQ_NOTE_EXEC",
    "track": "KQ_NOTE_TRACK",
    "trackerr": "KQ_NOTE_TRACKERR",
    "child": "KQ_NOTE_CHILD",
}


def constant(name, default=0):
    return getattr(select, name, default)


def available(name):
    return hasattr(select, name)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def timestamp():
    return utcnow().isoformat(timespec="microseconds")


def monotonic():
    return time.monotonic_ns()


def json_default(value):
    if isinstance(value, pathlib.Path):
        return str(value)
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, bytes):
        return value.hex()
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    if isinstance(value, BaseException):
        return {"type": type(value).__name__, "message": str(value)}
    return repr(value)


def encode_json(value, pretty=False):
    return json.dumps(value, default=json_default, ensure_ascii=False,
                      sort_keys=True, indent=2 if pretty else None)


def atomic_write(path, content):
    destination = pathlib.Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".kqueue-", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def safe_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def safe_float(value, default=None):
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError, OverflowError):
        return default


def safe_stat(path, follow=True):
    try:
        return os.stat(path, follow_symlinks=follow)
    except OSError:
        return None


def safe_readlink(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def safe_command(arguments, timeout=3.0):
    try:
        result = subprocess.run(arguments, capture_output=True, text=True,
                                timeout=timeout, check=False)
        return {"argv": arguments, "code": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": arguments, "error": str(exc)}


def named_bits(value, mapping):
    names = []
    known = 0
    for label, symbol in mapping.items():
        bit = constant(symbol)
        if bit and value & bit == bit:
            names.append(label)
            known |= bit
    if value & ~known:
        names.append(hex(value & ~known))
    return names


def filter_label(number):
    for label, symbol in FILTER_NAMES.items():
        if available(symbol) and number == constant(symbol):
            return label
    return str(number)


def clamp(value, low, high):
    return min(max(value, low), high)


def quantile(values, fraction):
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def describe_numbers(values):
    numbers = [float(v) for v in values if safe_float(v) is not None]
    if not numbers:
        return {"count": 0}
    return {
        "count": len(numbers),
        "min": min(numbers),
        "max": max(numbers),
        "mean": statistics.fmean(numbers),
        "median": statistics.median(numbers),
        "stdev": statistics.pstdev(numbers),
        "p50": quantile(numbers, 0.50),
        "p90": quantile(numbers, 0.90),
        "p95": quantile(numbers, 0.95),
        "p99": quantile(numbers, 0.99),
        "sum": sum(numbers),
    }


class ForensicsError(Exception):
    pass


class UnsupportedFeature(ForensicsError):
    pass


class RegistrationError(ForensicsError):
    pass


@dataclasses.dataclass
class EventRecord:
    sequence: int
    wall_time: str
    monotonic_ns: int
    elapsed_ms: float
    source: str
    kind: str
    identifier: int
    filter: str
    flags: list
    fflags: list
    data: int
    udata: typing.Any
    details: dict
    severity: str = "info"
    session: str = ""

    def as_dict(self):
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Registration:
    source: str
    kind: str
    identifier: int
    filter_number: int
    flags: int
    fflags: int
    data: int = 0
    details: dict = dataclasses.field(default_factory=dict)
    owned_fd: bool = False

    def as_dict(self):
        result = dataclasses.asdict(self)
        result["filter"] = filter_label(self.filter_number)
        result["flag_names"] = named_bits(self.flags, FLAG_NAMES)
        result["note_names"] = named_bits(self.fflags, NOTE_NAMES)
        return result


class JsonlSink:
    def __init__(self, path=None, flush=True):
        self.path = path
        self.flush = flush
        self.stream = None
        self.owns_stream = False
        self.lock = threading.RLock()
        self.count = 0

    def __enter__(self):
        if self.path and self.path != "-":
            destination = pathlib.Path(self.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            self.stream = destination.open("a", encoding="utf-8")
            self.owns_stream = True
        else:
            self.stream = sys.stdout
        return self

    def write(self, item):
        if self.stream is None:
            raise ForensicsError("sink is not open")
        payload = item.as_dict() if hasattr(item, "as_dict") else item
        with self.lock:
            self.stream.write(encode_json(payload) + "\n")
            if self.flush:
                self.stream.flush()
            self.count += 1

    def __exit__(self, exc_type, exc, tb):
        if self.owns_stream and self.stream is not None:
            self.stream.close()
        self.stream = None


class ConsoleSink:
    def __init__(self, stream=None, quiet=False):
        self.stream = stream or sys.stdout
        self.quiet = quiet
        self.count = 0

    def write(self, item):
        self.count += 1
        if self.quiet:
            return
        record = item.as_dict() if hasattr(item, "as_dict") else item
        if record.get("record_type") == "summary":
            self.stream.write(encode_json(record, pretty=True) + "\n")
            return
        time_value = record.get("wall_time", "")
        kind = record.get("kind", "event")
        source = record.get("source", "unknown")
        severity = record.get("severity", "info")
        data = record.get("data", "")
        flags = ",".join(record.get("fflags", []))
        self.stream.write(f"{time_value} {severity:7s} {kind:9s} {source} "
                          f"data={data} notes={flags}\n")
        self.stream.flush()


class MultiSink:
    def __init__(self, sinks):
        self.sinks = list(sinks)

    def write(self, item):
        for sink in self.sinks:
            sink.write(item)


class RingBuffer:
    def __init__(self, capacity=10000):
        self.capacity = max(1, capacity)
        self.items = collections.deque(maxlen=self.capacity)
        self.lock = threading.RLock()
        self.total = 0

    def append(self, value):
        with self.lock:
            self.items.append(value)
            self.total += 1

    def snapshot(self):
        with self.lock:
            return list(self.items)

    def __len__(self):
        with self.lock:
            return len(self.items)


class CounterSet:
    def __init__(self):
        self.lock = threading.RLock()
        self.counters = collections.Counter()

    def increment(self, name, amount=1):
        with self.lock:
            self.counters[name] += amount

    def snapshot(self):
        with self.lock:
            return dict(self.counters)


class SessionStats:
    def __init__(self):
        self.counts = collections.Counter()
        self.sources = collections.Counter()
        self.notes = collections.Counter()
        self.severities = collections.Counter()
        self.elapsed = []
        self.data_values = []
        self.timestamps = []
        self.errors = []
        self.lock = threading.RLock()

    def add(self, record):
        with self.lock:
            self.counts[record.kind] += 1
            self.sources[record.source] += 1
            self.severities[record.severity] += 1
            self.notes.update(record.fflags)
            self.elapsed.append(record.elapsed_ms)
            self.data_values.append(record.data)
            self.timestamps.append(record.monotonic_ns)
            if record.severity == "error":
                self.errors.append(record.as_dict())

    def summary(self):
        with self.lock:
            gaps = [(b - a) / 1_000_000 for a, b in
                    zip(self.timestamps, self.timestamps[1:])]
            return {
                "events": sum(self.counts.values()),
                "kinds": dict(self.counts),
                "sources": dict(self.sources),
                "notes": dict(self.notes),
                "severities": dict(self.severities),
                "elapsed_ms": describe_numbers(self.elapsed),
                "interarrival_ms": describe_numbers(gaps),
                "event_data": describe_numbers(self.data_values),
                "errors": self.errors[-20:],
            }


class RateWindow:
    def __init__(self, seconds=5.0):
        self.seconds = max(0.01, seconds)
        self.times = collections.deque()

    def observe(self, now):
        self.times.append(now)
        self.expire(now)
        return len(self.times) / self.seconds

    def expire(self, now):
        threshold = now - self.seconds
        while self.times and self.times[0] < threshold:
            self.times.popleft()


class SeverityPolicy:
    def __init__(self, warning_rate=100.0, critical_rate=1000.0):
        self.warning_rate = warning_rate
        self.critical_rate = critical_rate

    def classify(self, event, rate):
        if constant("KQ_EV_ERROR") and event.flags & constant("KQ_EV_ERROR"):
            return "error"
        if rate >= self.critical_rate:
            return "critical"
        if rate >= self.warning_rate:
            return "warning"
        if constant("KQ_EV_EOF") and event.flags & constant("KQ_EV_EOF"):
            return "notice"
        return "info"


class KqueueEngine:
    def __init__(self, sink, timeout=1.0, max_events=128, capacity=10000,
                 warning_rate=100.0, critical_rate=1000.0):
        if not hasattr(select, "kqueue") or not hasattr(select, "kevent"):
            raise UnsupportedFeature("Python kqueue support is unavailable on this platform")
        self.kq = select.kqueue()
        self.sink = sink
        self.timeout = max(0.0, timeout)
        self.max_events = clamp(max_events, 1, 4096)
        self.registrations = {}
        self.owned_fds = set()
        self.start_ns = monotonic()
        self.session = str(uuid.uuid4())
        self.sequence = 0
        self.stats = SessionStats()
        self.ring = RingBuffer(capacity)
        self.rate = RateWindow()
        self.policy = SeverityPolicy(warning_rate, critical_rate)
        self.stop_event = threading.Event()
        self.closed = False
        self.poll_count = 0
        self.empty_polls = 0
        self.registration_errors = []

    def register(self, registration):
        key = (registration.identifier, registration.filter_number)
        if key in self.registrations:
            raise RegistrationError(f"duplicate registration: {key}")
        event = select.kevent(registration.identifier,
                              filter=registration.filter_number,
                              flags=registration.flags,
                              fflags=registration.fflags,
                              data=registration.data)
        try:
            self.kq.control([event], 0, 0)
        except OSError as exc:
            self.registration_errors.append({"source": registration.source,
                                             "error": str(exc)})
            raise RegistrationError(str(exc)) from exc
        self.registrations[key] = registration
        if registration.owned_fd:
            self.owned_fds.add(registration.identifier)

    def unregister(self, registration):
        key = (registration.identifier, registration.filter_number)
        if key not in self.registrations:
            return
        event = select.kevent(registration.identifier,
                              filter=registration.filter_number,
                              flags=constant("KQ_EV_DELETE"))
        with contextlib.suppress(OSError):
            self.kq.control([event], 0, 0)
        self.registrations.pop(key, None)

    def decode(self, event):
        key = (event.ident, event.filter)
        registration = self.registrations.get(key)
        now_ns = monotonic()
        self.sequence += 1
        rate = self.rate.observe(now_ns / 1_000_000_000)
        kind = registration.kind if registration else filter_label(event.filter)
        source = registration.source if registration else f"ident:{event.ident}"
        details = dict(registration.details) if registration else {}
        details["rate_per_second"] = rate
        details["raw_flags"] = event.flags
        details["raw_fflags"] = event.fflags
        details["raw_filter"] = event.filter
        if event.flags & constant("KQ_EV_ERROR"):
            details["errno"] = event.data
            details["error_message"] = os.strerror(event.data) if event.data > 0 else "unknown"
        record = EventRecord(
            sequence=self.sequence,
            wall_time=timestamp(),
            monotonic_ns=now_ns,
            elapsed_ms=(now_ns - self.start_ns) / 1_000_000,
            source=source,
            kind=kind,
            identifier=event.ident,
            filter=filter_label(event.filter),
            flags=named_bits(event.flags, FLAG_NAMES),
            fflags=named_bits(event.fflags, NOTE_NAMES),
            data=event.data,
            udata=getattr(event, "udata", None),
            details=details,
            severity=self.policy.classify(event, rate),
            session=self.session,
        )
        return record

    def poll(self, timeout=None):
        self.poll_count += 1
        try:
            events = self.kq.control(None, self.max_events,
                                     self.timeout if timeout is None else timeout)
        except InterruptedError:
            return []
        if not events:
            self.empty_polls += 1
        records = []
        for event in events:
            record = self.decode(event)
            self.stats.add(record)
            self.ring.append(record)
            self.sink.write(record)
            records.append(record)
        return records

    def run(self, duration=None, limit=None, heartbeat=None):
        deadline = time.monotonic() + duration if duration is not None else None
        next_heartbeat = time.monotonic() + heartbeat if heartbeat else None
        try:
            while not self.stop_event.is_set():
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    break
                if limit is not None and self.sequence >= limit:
                    break
                remaining = deadline - now if deadline is not None else self.timeout
                wait = min(self.timeout, max(0.0, remaining))
                self.poll(wait)
                if next_heartbeat is not None and time.monotonic() >= next_heartbeat:
                    self.emit_heartbeat()
                    next_heartbeat = time.monotonic() + heartbeat
        except KeyboardInterrupt:
            self.stop_event.set()
        return self.summary()

    def emit_heartbeat(self):
        self.sink.write({"record_type": "heartbeat", "session": self.session,
                         "wall_time": timestamp(), "events": self.sequence,
                         "polls": self.poll_count,
                         "registrations": len(self.registrations)})

    def summary(self):
        result = self.stats.summary()
        result.update({
            "record_type": "summary",
            "session": self.session,
            "duration_seconds": (monotonic() - self.start_ns) / 1_000_000_000,
            "polls": self.poll_count,
            "empty_polls": self.empty_polls,
            "registrations": [r.as_dict() for r in self.registrations.values()],
            "registration_errors": self.registration_errors,
            "buffered_events": len(self.ring),
        })
        return result

    def stop(self):
        self.stop_event.set()

    def close(self):
        if self.closed:
            return
        self.closed = True
        with contextlib.suppress(OSError):
            self.kq.close()
        for fd in list(self.owned_fds):
            with contextlib.suppress(OSError):
                os.close(fd)
        self.owned_fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


def required_filter(name):
    symbol = FILTER_NAMES[name]
    if not available(symbol):
        raise UnsupportedFeature(f"{symbol} is unavailable")
    return constant(symbol)


def vnode_notes():
    names = ("delete", "write", "extend", "attrib", "link", "rename", "revoke")
    return sum(constant(NOTE_NAMES[name]) for name in names)


def proc_notes():
    names = ("exit", "fork", "exec", "track", "trackerr", "child")
    return sum(constant(NOTE_NAMES[name]) for name in names)


def add_vnode(engine, path, follow_symlinks=False):
    target = pathlib.Path(path).expanduser().absolute()
    flags = os.O_RDONLY
    if hasattr(os, "O_EVTONLY"):
        flags = os.O_EVTONLY
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(target), flags)
    registration = Registration(
        source=str(target), kind="vnode", identifier=fd,
        filter_number=required_filter("vnode"),
        flags=constant("KQ_EV_ADD") | constant("KQ_EV_CLEAR"),
        fflags=vnode_notes(),
        details={"path": str(target), "follow_symlinks": follow_symlinks},
        owned_fd=True,
    )
    try:
        engine.register(registration)
    except Exception:
        os.close(fd)
        raise
    return registration


def add_process(engine, pid, notes=None):
    if pid <= 0:
        raise ForensicsError("PID must be positive")
    if notes is None:
        notes = proc_notes()
    registration = Registration(
        source=f"pid:{pid}", kind="proc", identifier=pid,
        filter_number=required_filter("proc"),
        flags=constant("KQ_EV_ADD") | constant("KQ_EV_CLEAR"),
        fflags=notes,
        details={"pid": pid, "process": inspect_process(pid)},
    )
    engine.register(registration)
    return registration


def add_timer(engine, identifier=1, interval_ms=1000, oneshot=False):
    if interval_ms <= 0:
        raise ForensicsError("timer interval must be positive")
    flags = constant("KQ_EV_ADD") | constant("KQ_EV_ENABLE")
    if oneshot:
        flags |= constant("KQ_EV_ONESHOT")
    registration = Registration(
        source=f"timer:{identifier}", kind="timer", identifier=identifier,
        filter_number=required_filter("timer"), flags=flags,
        fflags=0, data=interval_ms,
        details={"interval_ms": interval_ms, "oneshot": oneshot},
    )
    engine.register(registration)
    return registration


def add_signal(engine, number):
    if number <= 0:
        raise ForensicsError("invalid signal")
    registration = Registration(
        source=f"signal:{signal.Signals(number).name}", kind="signal",
        identifier=number, filter_number=required_filter("signal"),
        flags=constant("KQ_EV_ADD") | constant("KQ_EV_ENABLE"),
        fflags=0,
        details={"signal": number, "name": signal.Signals(number).name},
    )
    engine.register(registration)
    return registration


def add_socket(engine, sock, direction="read", source=None):
    if direction not in ("read", "write"):
        raise ForensicsError("direction must be read or write")
    registration = Registration(
        source=source or f"socket:{sock.fileno()}", kind="socket",
        identifier=sock.fileno(), filter_number=required_filter(direction),
        flags=constant("KQ_EV_ADD") | constant("KQ_EV_ENABLE") |
              constant("KQ_EV_CLEAR"),
        fflags=0,
        details={"direction": direction, "family": str(sock.family),
                 "type": str(sock.type)},
    )
    engine.register(registration)
    return registration


def inspect_process(pid):
    if shutil.which("ps") is None:
        return {"pid": pid, "available": False}
    result = safe_command(["ps", "-p", str(pid), "-o", "pid=,ppid=,user=,stat=,comm="], 2)
    return {"pid": pid, "ps": result}


def inspect_path(path, hash_limit=0):
    target = pathlib.Path(path)
    result = {"path": str(target), "exists": target.exists(),
              "is_symlink": target.is_symlink(),
              "link_target": safe_readlink(target)}
    st = safe_stat(target, follow=False)
    if st is None:
        return result
    result.update({
        "mode": oct(st.st_mode), "inode": st.st_ino, "device": st.st_dev,
        "size": st.st_size, "uid": st.st_uid, "gid": st.st_gid,
        "nlink": st.st_nlink, "mtime_ns": st.st_mtime_ns,
        "ctime_ns": st.st_ctime_ns, "atime_ns": st.st_atime_ns,
        "is_directory": target.is_dir(), "is_file": target.is_file(),
    })
    if hash_limit and target.is_file() and st.st_size <= hash_limit:
        digest = hashlib.sha256()
        try:
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    digest.update(chunk)
            result["sha256"] = digest.hexdigest()
        except OSError as exc:
            result["hash_error"] = str(exc)
    return result


def snapshot_directory(path, recursive=False, max_entries=10000, hash_limit=0):
    root = pathlib.Path(path).expanduser().absolute()
    result = {"root": str(root), "entries": {}, "truncated": False,
              "errors": [], "created_at": timestamp()}
    pending = collections.deque([root])
    while pending:
        current = pending.popleft()
        try:
            children = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            result["errors"].append({"path": str(current), "error": str(exc)})
            continue
        for child in children:
            if len(result["entries"]) >= max_entries:
                result["truncated"] = True
                return result
            relative = str(child.relative_to(root))
            result["entries"][relative] = inspect_path(child, hash_limit)
            if recursive and child.is_dir() and not child.is_symlink():
                pending.append(child)
    return result


def compare_snapshots(before, after):
    old = before.get("entries", {})
    new = after.get("entries", {})
    old_names = set(old)
    new_names = set(new)
    changed = {}
    for name in sorted(old_names & new_names):
        left = old[name]
        right = new[name]
        fields = sorted(set(left) | set(right))
        delta = {field: {"before": left.get(field), "after": right.get(field)}
                 for field in fields if left.get(field) != right.get(field)}
        if delta:
            changed[name] = delta
    return {"added": sorted(new_names - old_names),
            "removed": sorted(old_names - new_names),
            "changed": changed,
            "counts": {"added": len(new_names - old_names),
                       "removed": len(old_names - new_names),
                       "changed": len(changed)}}


def system_facts():
    result = {
        "timestamp": timestamp(), "application": APP_NAME,
        "version": APP_VERSION, "python": sys.version,
        "executable": sys.executable, "platform": platform.platform(),
        "system": platform.system(), "release": platform.release(),
        "machine": platform.machine(), "hostname": socket.gethostname(),
        "pid": os.getpid(), "uid": os.getuid() if hasattr(os, "getuid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "cwd": os.getcwd(), "kqueue_available": hasattr(select, "kqueue"),
        "kevent_available": hasattr(select, "kevent"),
        "filters": {name: {"available": available(symbol),
                            "value": getattr(select, symbol, None)}
                    for name, symbol in FILTER_NAMES.items()},
        "flags": {name: getattr(select, symbol, None)
                  for name, symbol in FLAG_NAMES.items()},
        "notes": {name: getattr(select, symbol, None)
                  for name, symbol in NOTE_NAMES.items()},
    }
    with contextlib.suppress(Exception):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        result["nofile"] = {"soft": soft, "hard": hard}
    if platform.system() == "FreeBSD":
        for key in ("kern.ostype", "kern.osrelease", "kern.osrevision",
                    "kern.version", "kern.maxfiles", "kern.maxfilesperproc",
                    "kern.maxproc", "kern.maxprocperuid", "hw.ncpu",
                    "vm.stats.vm.v_free_count"):
            result.setdefault("sysctl", {})[key] = safe_command(["sysctl", "-n", key])
        result["freebsd_version"] = safe_command(["freebsd-version", "-kru"])
    return result


def parse_signal(value):
    if value.isdigit():
        return int(value)
    name = value.upper()
    if not name.startswith("SIG"):
        name = "SIG" + name
    member = getattr(signal, name, None)
    if member is None:
        raise ForensicsError(f"unknown signal: {value}")
    return int(member)


def parse_duration(value):
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError(f"invalid duration: {value}")
    number = float(match.group(1))
    unit = (match.group(2) or "s").lower()
    return number * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


def positive_int(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return result


def nonnegative_int(value):
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return result


def add_engine_arguments(parser):
    parser.add_argument("--duration", type=parse_duration)
    parser.add_argument("--limit", type=positive_int)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--max-events", type=positive_int, default=128)
    parser.add_argument("--capacity", type=positive_int, default=10000)
    parser.add_argument("--warning-rate", type=float, default=100.0)
    parser.add_argument("--critical-rate", type=float, default=1000.0)
    parser.add_argument("--heartbeat", type=parse_duration)
    parser.add_argument("--jsonl")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--summary-file")


def make_engine(args, sink):
    return KqueueEngine(
        sink=sink, timeout=args.timeout, max_events=args.max_events,
        capacity=args.capacity, warning_rate=args.warning_rate,
        critical_rate=args.critical_rate)


def monitored_run(args, register):
    console = ConsoleSink(quiet=args.quiet)
    if args.jsonl:
        with JsonlSink(args.jsonl) as journal:
            sink = MultiSink([console, journal]) if args.jsonl != "-" else journal
            with make_engine(args, sink) as engine:
                register(engine)
                result = engine.run(args.duration, args.limit, args.heartbeat)
                sink.write(result)
    else:
        with make_engine(args, console) as engine:
            register(engine)
            result = engine.run(args.duration, args.limit, args.heartbeat)
            console.write(result)
    if args.summary_file:
        atomic_write(args.summary_file, encode_json(result, pretty=True) + "\n")
    return 0


def command_watch(args):
    def register(engine):
        for path in args.paths:
            add_vnode(engine, path, args.follow_symlinks)
    return monitored_run(args, register)


def command_proc(args):
    def register(engine):
        for pid in args.pids:
            add_process(engine, pid)
    return monitored_run(args, register)


def command_timer(args):
    def register(engine):
        for index in range(args.count):
            add_timer(engine, index + 1, args.interval_ms, args.oneshot)
    return monitored_run(args, register)


def command_signal(args):
    numbers = [parse_signal(value) for value in args.signals]
    old_handlers = {}
    def handler(signum, frame):
        return None
    for number in numbers:
        old_handlers[number] = signal.getsignal(number)
        signal.signal(number, handler)
    try:
        def register(engine):
            for number in numbers:
                add_signal(engine, number)
        return monitored_run(args, register)
    finally:
        for number, previous in old_handlers.items():
            signal.signal(number, previous)


def command_snapshot(args):
    result = snapshot_directory(args.path, args.recursive, args.max_entries,
                                args.hash_limit)
    payload = encode_json(result, pretty=True) + "\n"
    if args.output:
        atomic_write(args.output, payload)
    else:
        sys.stdout.write(payload)
    return 0


def command_diff(args):
    with open(args.before, encoding="utf-8") as stream:
        before = json.load(stream)
    with open(args.after, encoding="utf-8") as stream:
        after = json.load(stream)
    result = compare_snapshots(before, after)
    payload = encode_json(result, pretty=True) + "\n"
    if args.output:
        atomic_write(args.output, payload)
    else:
        sys.stdout.write(payload)
    return 0


def command_doctor(args):
    facts = system_facts()
    tests = {}
    if hasattr(select, "kqueue"):
        try:
            kq = select.kqueue()
            try:
                tests["create_kqueue"] = {"ok": True, "fileno": kq.fileno()}
            finally:
                kq.close()
        except OSError as exc:
            tests["create_kqueue"] = {"ok": False, "error": str(exc)}
    else:
        tests["create_kqueue"] = {"ok": False, "error": "unavailable"}
    facts["tests"] = tests
    sys.stdout.write(encode_json(facts, pretty=True) + "\n")
    return 0 if tests["create_kqueue"]["ok"] else 2


def command_constants(args):
    data = {"filters": {}, "flags": {}, "notes": {}}
    for group, mapping in (("filters", FILTER_NAMES), ("flags", FLAG_NAMES),
                           ("notes", NOTE_NAMES)):
        for name, symbol in mapping.items():
            data[group][name] = {"symbol": symbol,
                                 "value": getattr(select, symbol, None)}
    sys.stdout.write(encode_json(data, pretty=True) + "\n")
    return 0


def load_jsonl(path, strict=False):
    with open(path, "r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("JSONL record is not an object")
                yield value
            except (ValueError, json.JSONDecodeError) as exc:
                if strict:
                    raise ForensicsError(f"line {line_number}: {exc}") from exc


def filter_records(records, kinds=None, severities=None, sources=None,
                   start_ms=None, end_ms=None):
    for record in records:
        if record.get("record_type") in ("summary", "heartbeat"):
            continue
        if kinds and record.get("kind") not in kinds:
            continue
        if severities and record.get("severity") not in severities:
            continue
        if sources and not any(fnmatch.fnmatch(record.get("source", ""), p)
                               for p in sources):
            continue
        elapsed = safe_float(record.get("elapsed_ms"))
        if start_ms is not None and (elapsed is None or elapsed < start_ms):
            continue
        if end_ms is not None and (elapsed is None or elapsed > end_ms):
            continue
        yield record


def summarize_records(records):
    counts = collections.Counter()
    sources = collections.Counter()
    severities = collections.Counter()
    notes = collections.Counter()
    sessions = collections.Counter()
    data_values = []
    elapsed = []
    timestamps = []
    errors = []
    for record in records:
        counts[record.get("kind", "unknown")] += 1
        sources[record.get("source", "unknown")] += 1
        severities[record.get("severity", "unknown")] += 1
        notes.update(record.get("fflags", []))
        sessions[record.get("session", "unknown")] += 1
        value = safe_float(record.get("data"))
        if value is not None:
            data_values.append(value)
        value = safe_float(record.get("elapsed_ms"))
        if value is not None:
            elapsed.append(value)
        value = safe_int(record.get("monotonic_ns"))
        if value is not None:
            timestamps.append(value)
        if record.get("severity") == "error":
            errors.append(record)
    timestamps.sort()
    gaps = [(b - a) / 1_000_000 for a, b in zip(timestamps, timestamps[1:])]
    return {"total": sum(counts.values()), "kinds": dict(counts),
            "sources": dict(sources), "severities": dict(severities),
            "notes": dict(notes), "sessions": dict(sessions),
            "data": describe_numbers(data_values),
            "elapsed_ms": describe_numbers(elapsed),
            "interarrival_ms": describe_numbers(gaps),
            "errors": errors[-50:]}


def command_analyze(args):
    records = filter_records(load_jsonl(args.path, args.strict),
                             args.kind, args.severity, args.source,
                             args.start_ms, args.end_ms)
    result = summarize_records(records)
    payload = encode_json(result, pretty=True) + "\n"
    if args.output:
        atomic_write(args.output, payload)
    else:
        sys.stdout.write(payload)
    return 0


def command_export(args):
    records = filter_records(load_jsonl(args.path, args.strict),
                             args.kind, args.severity, args.source,
                             args.start_ms, args.end_ms)
    fields = ("sequence", "wall_time", "elapsed_ms", "source", "kind",
              "identifier", "filter", "flags", "fflags", "data", "severity",
              "session", "details")
    output = sys.stdout if args.output == "-" else open(args.output, "w", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = {name: record.get(name) for name in fields}
            for name in ("flags", "fflags", "details"):
                row[name] = encode_json(row[name])
            writer.writerow(row)
    finally:
        if output is not sys.stdout:
            output.close()
    return 0


def command_replay(args):
    records = list(filter_records(load_jsonl(args.path, args.strict),
                                  args.kind, args.severity, args.source,
                                  args.start_ms, args.end_ms))
    sink = ConsoleSink(quiet=False)
    previous = None
    for record in records:
        elapsed = safe_float(record.get("elapsed_ms"))
        if args.speed > 0 and previous is not None and elapsed is not None:
            delay = max(0.0, (elapsed - previous) / 1000 / args.speed)
            time.sleep(min(delay, args.max_sleep))
        sink.write(record)
        if elapsed is not None:
            previous = elapsed
    return 0


def command_process_info(args):
    data = {"processes": [inspect_process(pid) for pid in args.pids]}
    sys.stdout.write(encode_json(data, pretty=True) + "\n")
    return 0


def command_path_info(args):
    data = {"paths": [inspect_path(path, args.hash_limit) for path in args.paths]}
    sys.stdout.write(encode_json(data, pretty=True) + "\n")
    return 0


def command_benchmark(args):
    measurements = []
    with KqueueEngine(ConsoleSink(quiet=True), timeout=args.timeout) as engine:
        add_timer(engine, 1, args.interval_ms)
        for index in range(args.samples):
            started = monotonic()
            records = engine.poll(args.timeout)
            elapsed = (monotonic() - started) / 1_000_000
            measurements.append({"iteration": index + 1, "elapsed_ms": elapsed,
                                 "events": len(records)})
        result = {"samples": args.samples,
                  "interval_ms": args.interval_ms,
                  "poll_latency_ms": describe_numbers([x["elapsed_ms"] for x in measurements]),
                  "events_per_poll": describe_numbers([x["events"] for x in measurements]),
                  "session": engine.summary()}
    sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0


def command_selftest(args):
    results = []
    def run_test(name, operation):
        started = monotonic()
        try:
            details = operation()
            results.append({"name": name, "ok": True,
                            "duration_ms": (monotonic() - started) / 1_000_000,
                            "details": details})
        except Exception as exc:
            results.append({"name": name, "ok": False,
                            "duration_ms": (monotonic() - started) / 1_000_000,
                            "error": str(exc)})
    def timer_test():
        with KqueueEngine(ConsoleSink(quiet=True), timeout=0.1) as engine:
            add_timer(engine, 1, 10, oneshot=True)
            return {"events": len(engine.poll(0.5))}
    def vnode_test():
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "watched"
            path.write_text("before", encoding="utf-8")
            with KqueueEngine(ConsoleSink(quiet=True), timeout=0.1) as engine:
                add_vnode(engine, path)
                path.write_text("after", encoding="utf-8")
                return {"events": len(engine.poll(0.5))}
    def snapshot_test():
        with tempfile.TemporaryDirectory() as directory:
            before = snapshot_directory(directory)
            pathlib.Path(directory, "created").write_text("x", encoding="utf-8")
            after = snapshot_directory(directory)
            return compare_snapshots(before, after)
    def numeric_test():
        return describe_numbers([1, 2, 3, 4, 5])
    run_test("timer", timer_test)
    run_test("vnode", vnode_test)
    run_test("snapshot", snapshot_test)
    run_test("statistics", numeric_test)
    passed = sum(item["ok"] for item in results)
    sys.stdout.write(encode_json({"passed": passed, "failed": len(results) - passed,
                                  "tests": results}, pretty=True) + "\n")
    return 0 if passed == len(results) else 2


def build_parser():
    parser = argparse.ArgumentParser(prog=APP_NAME,
                                     description="FreeBSD kqueue event forensics and telemetry")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    watch = sub.add_parser("watch", help="monitor vnode events")
    watch.add_argument("paths", nargs="+")
    watch.add_argument("--follow-symlinks", action="store_true")
    add_engine_arguments(watch)
    watch.set_defaults(func=command_watch)
    proc = sub.add_parser("proc", help="monitor process lifecycle")
    proc.add_argument("pids", nargs="+", type=positive_int)
    add_engine_arguments(proc)
    proc.set_defaults(func=command_proc)
    timer = sub.add_parser("timer", help="monitor kernel timers")
    timer.add_argument("--interval-ms", type=positive_int, default=1000)
    timer.add_argument("--count", type=positive_int, default=1)
    timer.add_argument("--oneshot", action="store_true")
    add_engine_arguments(timer)
    timer.set_defaults(func=command_timer)
    signals = sub.add_parser("signal", help="monitor process signals")
    signals.add_argument("signals", nargs="+", help="signal names or numbers")
    add_engine_arguments(signals)
    signals.set_defaults(func=command_signal)
    snap = sub.add_parser("snapshot", help="capture filesystem metadata")
    snap.add_argument("path")
    snap.add_argument("--recursive", action="store_true")
    snap.add_argument("--max-entries", type=positive_int, default=10000)
    snap.add_argument("--hash-limit", type=nonnegative_int, default=0)
    snap.add_argument("--output")
    snap.set_defaults(func=command_snapshot)
    diff = sub.add_parser("diff", help="compare filesystem snapshots")
    diff.add_argument("before")
    diff.add_argument("after")
    diff.add_argument("--output")
    diff.set_defaults(func=command_diff)
    doctor = sub.add_parser("doctor", help="inspect platform and kqueue support")
    doctor.set_defaults(func=command_doctor)
    constants = sub.add_parser("constants", help="show available kqueue constants")
    constants.set_defaults(func=command_constants)
    for name, func in (("analyze", command_analyze),
                       ("export", command_export), ("replay", command_replay)):
        p = sub.add_parser(name, help=f"{name} captured JSONL events")
        p.add_argument("path")
        p.add_argument("--kind", action="append")
        p.add_argument("--severity", action="append")
        p.add_argument("--source", action="append")
        p.add_argument("--start-ms", type=float)
        p.add_argument("--end-ms", type=float)
        p.add_argument("--strict", action="store_true")
        if name != "replay":
            p.add_argument("--output")
        if name == "export":
            p.set_defaults(output="-")
        if name == "replay":
            p.add_argument("--speed", type=float, default=1.0)
            p.add_argument("--max-sleep", type=float, default=5.0)
        p.set_defaults(func=func)
    pinfo = sub.add_parser("process-info", help="inspect process metadata")
    pinfo.add_argument("pids", nargs="+", type=positive_int)
    pinfo.set_defaults(func=command_process_info)
    finfo = sub.add_parser("path-info", help="inspect filesystem objects")
    finfo.add_argument("paths", nargs="+")
    finfo.add_argument("--hash-limit", type=nonnegative_int, default=0)
    finfo.set_defaults(func=command_path_info)
    benchmark = sub.add_parser("benchmark", help="benchmark timer dispatch")
    benchmark.add_argument("--samples", type=positive_int, default=100)
    benchmark.add_argument("--interval-ms", type=positive_int, default=10)
    benchmark.add_argument("--timeout", type=float, default=1.0)
    benchmark.set_defaults(func=command_benchmark)
    selftest = sub.add_parser("selftest", help="exercise supported probes")
    selftest.set_defaults(func=command_selftest)
    return parser


class EventTimeline:
    def __init__(self, bucket_seconds=1.0):
        self.bucket_seconds = max(0.001, bucket_seconds)
        self.buckets = collections.defaultdict(collections.Counter)
        self.first = None
        self.last = None

    def add(self, record):
        elapsed = safe_float(record.get("elapsed_ms"))
        if elapsed is None:
            return
        second = elapsed / 1000.0
        bucket = int(second / self.bucket_seconds)
        self.buckets[bucket][record.get("kind", "unknown")] += 1
        self.first = second if self.first is None else min(self.first, second)
        self.last = second if self.last is None else max(self.last, second)

    def report(self):
        return {
            "bucket_seconds": self.bucket_seconds,
            "first_second": self.first,
            "last_second": self.last,
            "buckets": [
                {"index": index, "start_second": index * self.bucket_seconds,
                 "end_second": (index + 1) * self.bucket_seconds,
                 "total": sum(counter.values()), "kinds": dict(counter)}
                for index, counter in sorted(self.buckets.items())
            ],
        }


class EventCorrelator:
    def __init__(self, window_ms=100.0):
        self.window_ms = max(0.0, window_ms)
        self.events = collections.deque()
        self.pairs = collections.Counter()
        self.total = 0

    def add(self, record):
        elapsed = safe_float(record.get("elapsed_ms"))
        if elapsed is None:
            return
        while self.events and elapsed - self.events[0][0] > self.window_ms:
            self.events.popleft()
        source = record.get("source", "unknown")
        kind = record.get("kind", "unknown")
        for previous_time, previous_source, previous_kind in self.events:
            if previous_source == source:
                continue
            pair = (previous_kind, kind)
            self.pairs[pair] += 1
            self.total += 1
        self.events.append((elapsed, source, kind))

    def report(self, top=50):
        return {"window_ms": self.window_ms, "total_pairs": self.total,
                "top_pairs": [{"from": a, "to": b, "count": count}
                              for (a, b), count in self.pairs.most_common(top)]}


class EntropyAnalyzer:
    def __init__(self):
        self.counts = collections.Counter()

    def add(self, value):
        self.counts[str(value)] += 1

    def entropy(self):
        total = sum(self.counts.values())
        if not total:
            return 0.0
        return -sum((count / total) * math.log2(count / total)
                    for count in self.counts.values())

    def report(self):
        return {"entropy_bits": self.entropy(),
                "distinct": len(self.counts),
                "observations": sum(self.counts.values()),
                "distribution": dict(self.counts)}


class SequenceAnalyzer:
    def __init__(self):
        self.last = None
        self.duplicates = 0
        self.regressions = 0
        self.gaps = 0
        self.minimum = None
        self.maximum = None
        self.total = 0

    def add(self, value):
        number = safe_int(value)
        if number is None:
            return
        if self.last is not None:
            if number == self.last:
                self.duplicates += 1
            elif number < self.last:
                self.regressions += 1
            elif number > self.last + 1:
                self.gaps += number - self.last - 1
        self.last = number
        self.total += 1
        self.minimum = number if self.minimum is None else min(self.minimum, number)
        self.maximum = number if self.maximum is None else max(self.maximum, number)

    def report(self):
        return {"observations": self.total, "duplicates": self.duplicates,
                "regressions": self.regressions, "missing_sequence_values": self.gaps,
                "minimum": self.minimum, "maximum": self.maximum}


class AnomalyDetector:
    def __init__(self, warmup=20, sigma=3.0, window=100):
        self.warmup = warmup
        self.sigma = sigma
        self.window = max(2, window)
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=self.window))
        self.anomalies = []

    def add(self, key, value, context=None):
        number = safe_float(value)
        if number is None:
            return None
        history = self.history[key]
        result = None
        if len(history) >= self.warmup:
            mean = statistics.fmean(history)
            deviation = statistics.pstdev(history)
            if deviation > 0:
                zscore = abs(number - mean) / deviation
                if zscore >= self.sigma:
                    result = {"key": key, "value": number, "mean": mean,
                              "stdev": deviation, "zscore": zscore,
                              "context": context}
                    self.anomalies.append(result)
        history.append(number)
        return result

    def report(self, limit=100):
        return {"total": len(self.anomalies),
                "recent": self.anomalies[-limit:],
                "series": {key: len(value) for key, value in self.history.items()}}


class EventProfiler:
    def __init__(self, bucket_seconds=1.0, correlation_ms=100.0,
                 anomaly_sigma=3.0):
        self.timeline = EventTimeline(bucket_seconds)
        self.correlator = EventCorrelator(correlation_ms)
        self.kind_entropy = EntropyAnalyzer()
        self.source_entropy = EntropyAnalyzer()
        self.sequence = SequenceAnalyzer()
        self.anomalies = AnomalyDetector(sigma=anomaly_sigma)
        self.previous_by_source = {}
        self.count = 0

    def add(self, record):
        self.count += 1
        self.timeline.add(record)
        self.correlator.add(record)
        self.kind_entropy.add(record.get("kind"))
        self.source_entropy.add(record.get("source"))
        self.sequence.add(record.get("sequence"))
        source = record.get("source", "unknown")
        elapsed = safe_float(record.get("elapsed_ms"))
        if elapsed is not None:
            previous = self.previous_by_source.get(source)
            if previous is not None:
                self.anomalies.add(source, elapsed - previous,
                                   {"sequence": record.get("sequence")})
            self.previous_by_source[source] = elapsed

    def report(self):
        return {"events": self.count,
                "timeline": self.timeline.report(),
                "correlations": self.correlator.report(),
                "kind_entropy": self.kind_entropy.report(),
                "source_entropy": self.source_entropy.report(),
                "sequence_integrity": self.sequence.report(),
                "anomalies": self.anomalies.report()}


def command_profile(args):
    profiler = EventProfiler(args.bucket_seconds, args.correlation_ms,
                             args.anomaly_sigma)
    records = filter_records(load_jsonl(args.path, args.strict),
                             args.kind, args.severity, args.source,
                             args.start_ms, args.end_ms)
    for record in records:
        profiler.add(record)
    result = profiler.report()
    payload = encode_json(result, pretty=True) + "\n"
    if args.output:
        atomic_write(args.output, payload)
    else:
        sys.stdout.write(payload)
    return 0


def inspect_socket(sock):
    result = {"fileno": sock.fileno(), "family": str(sock.family),
              "type": str(sock.type), "proto": sock.proto,
              "blocking": sock.getblocking()}
    for name, operation in (("local", sock.getsockname),
                            ("peer", sock.getpeername)):
        try:
            result[name] = operation()
        except OSError as exc:
            result[name + "_error"] = str(exc)
    for level, option, name in (
        (socket.SOL_SOCKET, socket.SO_RCVBUF, "receive_buffer"),
        (socket.SOL_SOCKET, socket.SO_SNDBUF, "send_buffer"),
        (socket.SOL_SOCKET, socket.SO_ERROR, "socket_error"),
        (socket.SOL_SOCKET, socket.SO_REUSEADDR, "reuse_address"),
    ):
        try:
            result[name] = sock.getsockopt(level, option)
        except OSError:
            pass
    return result


class SocketServer:
    def __init__(self, host="127.0.0.1", port=0, backlog=128):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.listener = None
        self.clients = {}
        self.accepted = 0
        self.received_bytes = 0
        self.sent_bytes = 0
        self.closed = 0
        self.errors = []

    def open(self):
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setblocking(False)
        self.listener.bind((self.host, self.port))
        self.listener.listen(self.backlog)
        return self.listener.getsockname()

    def accept(self, limit=128):
        accepted = []
        for _ in range(limit):
            try:
                client, address = self.listener.accept()
            except BlockingIOError:
                break
            except OSError as exc:
                self.errors.append(str(exc))
                break
            client.setblocking(False)
            self.clients[client.fileno()] = client
            self.accepted += 1
            accepted.append((client, address))
        return accepted

    def receive(self, fd, size=65536, echo=False):
        client = self.clients.get(fd)
        if client is None:
            return {"status": "unknown"}
        try:
            data = client.recv(size)
        except BlockingIOError:
            return {"status": "would_block"}
        except OSError as exc:
            self.disconnect(fd)
            return {"status": "error", "error": str(exc)}
        if not data:
            self.disconnect(fd)
            return {"status": "eof"}
        self.received_bytes += len(data)
        result = {"status": "received", "bytes": len(data),
                  "sha256": hashlib.sha256(data).hexdigest(),
                  "preview_hex": data[:64].hex()}
        if echo:
            try:
                sent = client.send(data)
                self.sent_bytes += sent
                result["echoed_bytes"] = sent
                result["unsent_bytes"] = len(data) - sent
            except (BlockingIOError, OSError) as exc:
                result["echo_error"] = str(exc)
        return result

    def disconnect(self, fd):
        client = self.clients.pop(fd, None)
        if client is not None:
            with contextlib.suppress(OSError):
                client.close()
            self.closed += 1

    def close(self):
        for fd in list(self.clients):
            self.disconnect(fd)
        if self.listener is not None:
            with contextlib.suppress(OSError):
                self.listener.close()
            self.listener = None

    def summary(self):
        return {"accepted": self.accepted, "active": len(self.clients),
                "closed": self.closed, "received_bytes": self.received_bytes,
                "sent_bytes": self.sent_bytes, "errors": self.errors[-20:]}


class NetworkSession:
    def __init__(self, engine, server, echo=False):
        self.engine = engine
        self.server = server
        self.echo = echo
        self.listener_registration = None
        self.client_registrations = {}
        self.actions = []

    def start(self):
        address = self.server.open()
        self.listener_registration = add_socket(self.engine, self.server.listener,
                                                "read", f"listener:{address}")
        return address

    def process(self, records):
        for record in records:
            if record.kind != "socket":
                continue
            fd = record.identifier
            if self.server.listener and fd == self.server.listener.fileno():
                for client, address in self.server.accept():
                    registration = add_socket(self.engine, client, "read",
                                              f"client:{address}")
                    self.client_registrations[client.fileno()] = registration
                    self.actions.append({"type": "accept", "peer": address,
                                         "fd": client.fileno(), "time": timestamp()})
            elif fd in self.client_registrations:
                outcome = self.server.receive(fd, echo=self.echo)
                self.actions.append({"type": "receive", "fd": fd,
                                     "time": timestamp(), "outcome": outcome})
                if outcome["status"] in ("eof", "error"):
                    self.engine.unregister(self.client_registrations.pop(fd))

    def close(self):
        self.server.close()

    def summary(self):
        return {"server": self.server.summary(),
                "actions": self.actions[-100:],
                "total_actions": len(self.actions)}


def command_listen(args):
    console = ConsoleSink(quiet=args.quiet)
    with contextlib.ExitStack() as stack:
        if args.jsonl:
            journal = stack.enter_context(JsonlSink(args.jsonl))
            sink = journal if args.jsonl == "-" else MultiSink([console, journal])
        else:
            sink = console
        engine = stack.enter_context(make_engine(args, sink))
        server = SocketServer(args.host, args.port, args.backlog)
        network = NetworkSession(engine, server, args.echo)
        try:
            address = network.start()
            sys.stderr.write(f"listening on {address}\n")
            deadline = time.monotonic() + args.duration if args.duration else None
            while not engine.stop_event.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    break
                if args.limit and engine.sequence >= args.limit:
                    break
                records = engine.poll()
                network.process(records)
        except KeyboardInterrupt:
            pass
        finally:
            summary = {"record_type": "summary", "kqueue": engine.summary(),
                       "network": network.summary()}
            sink.write(summary)
            if args.summary_file:
                atomic_write(args.summary_file, encode_json(summary, pretty=True) + "\n")
            network.close()
    return 0


def command_connect(args):
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    started = monotonic()
    error = sock.connect_ex((args.host, args.port))
    result = {"target": [args.host, args.port], "connect_ex": error,
              "initial_error": os.strerror(error) if error else None}
    try:
        with KqueueEngine(ConsoleSink(quiet=True), timeout=args.timeout) as engine:
            add_socket(engine, sock, "write", "connect")
            records = engine.poll(args.timeout)
            result["events"] = [record.as_dict() for record in records]
            result["socket_error"] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            result["elapsed_ms"] = (monotonic() - started) / 1_000_000
            result["socket"] = inspect_socket(sock)
    finally:
        sock.close()
    sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0 if result.get("socket_error") == 0 else 2


def command_udp(args):
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind((args.host, args.port))
    result = {"bound": sock.getsockname(), "packets": 0,
              "bytes": 0, "senders": collections.Counter(), "errors": []}
    try:
        console = ConsoleSink(quiet=args.quiet)
        with contextlib.ExitStack() as stack:
            if args.jsonl:
                journal = stack.enter_context(JsonlSink(args.jsonl))
                sink = journal if args.jsonl == "-" else MultiSink([console, journal])
            else:
                sink = console
            engine = stack.enter_context(make_engine(args, sink))
            add_socket(engine, sock, "read", f"udp:{sock.getsockname()}")
            deadline = time.monotonic() + args.duration if args.duration else None
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                if args.limit and result["packets"] >= args.limit:
                    break
                records = engine.poll()
                if not records:
                    continue
                for _ in range(args.batch):
                    try:
                        payload, address = sock.recvfrom(args.buffer_size)
                    except BlockingIOError:
                        break
                    except OSError as exc:
                        result["errors"].append(str(exc))
                        break
                    result["packets"] += 1
                    result["bytes"] += len(payload)
                    result["senders"][str(address)] += 1
                    sink.write({"record_type": "datagram", "wall_time": timestamp(),
                                "source": str(address), "bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "preview_hex": payload[:64].hex()})
            result["senders"] = dict(result["senders"])
            result["kqueue"] = engine.summary()
            sink.write({"record_type": "summary", "udp": result})
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return 0


def compare_sessions(left, right):
    result = {"metrics": {}, "kind_delta": {}, "source_delta": {},
              "severity_delta": {}}
    for name in ("total", "events", "polls", "empty_polls"):
        a = safe_float(left.get(name))
        b = safe_float(right.get(name))
        if a is not None and b is not None:
            result["metrics"][name] = {"left": a, "right": b,
                                       "delta": b - a,
                                       "ratio": b / a if a else None}
    for field, output in (("kinds", "kind_delta"),
                          ("sources", "source_delta"),
                          ("severities", "severity_delta")):
        first = left.get(field, {})
        second = right.get(field, {})
        for key in sorted(set(first) | set(second)):
            a = first.get(key, 0)
            b = second.get(key, 0)
            result[output][key] = {"left": a, "right": b, "delta": b - a}
    return result


def command_compare(args):
    with open(args.left, encoding="utf-8") as stream:
        left = json.load(stream)
    with open(args.right, encoding="utf-8") as stream:
        right = json.load(stream)
    result = compare_sessions(left, right)
    payload = encode_json(result, pretty=True) + "\n"
    if args.output:
        atomic_write(args.output, payload)
    else:
        sys.stdout.write(payload)
    return 0


def read_sysctl(name):
    result = safe_command(["sysctl", "-n", name])
    if result.get("code") == 0:
        return {"name": name, "value": result["stdout"], "ok": True}
    return {"name": name, "ok": False,
            "error": result.get("stderr") or result.get("error")}


def command_sysctl(args):
    names = args.names or [
        "kern.ostype", "kern.osrelease", "kern.osrevision",
        "kern.maxfiles", "kern.maxfilesperproc", "kern.maxproc",
        "kern.maxprocperuid", "kern.ipc.somaxconn", "hw.ncpu",
        "net.inet.tcp.msl", "net.inet.tcp.syncookies",
        "net.inet.ip.forwarding", "security.bsd.see_other_uids",
        "security.bsd.unprivileged_read_msgbuf",
    ]
    result = {"timestamp": timestamp(),
              "values": [read_sysctl(name) for name in names]}
    if args.output:
        atomic_write(args.output, encode_json(result, pretty=True) + "\n")
    else:
        sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0


def compare_sysctls(left, right):
    old = {item["name"]: item for item in left.get("values", [])}
    new = {item["name"]: item for item in right.get("values", [])}
    changes = {}
    for name in sorted(set(old) | set(new)):
        a = old.get(name)
        b = new.get(name)
        if a != b:
            changes[name] = {"before": a, "after": b}
    return {"changed": changes, "count": len(changes)}


def command_sysctl_diff(args):
    with open(args.before, encoding="utf-8") as stream:
        before = json.load(stream)
    with open(args.after, encoding="utf-8") as stream:
        after = json.load(stream)
    sys.stdout.write(encode_json(compare_sysctls(before, after), pretty=True) + "\n")
    return 0


def inspect_limits():
    result = {}
    for name in dir(resource):
        if not name.startswith("RLIMIT_"):
            continue
        value = getattr(resource, name)
        if not isinstance(value, int):
            continue
        try:
            soft, hard = resource.getrlimit(value)
            result[name] = {"soft": soft, "hard": hard}
        except (OSError, ValueError):
            pass
    return result


def command_limits(args):
    data = {"timestamp": timestamp(), "limits": inspect_limits()}
    sys.stdout.write(encode_json(data, pretty=True) + "\n")
    return 0


def command_health(args):
    facts = system_facts()
    facts["limits"] = inspect_limits()
    facts["packages"] = {}
    if platform.system() == "FreeBSD":
        facts["packages"]["audit"] = safe_command(["pkg", "audit"], 10)
        facts["packages"]["repositories"] = safe_command(["pkg", "repos"], 5)
        facts["packages"]["kernel"] = safe_command(
            ["pkg", "info", "-x", "FreeBSD-kernel"], 5)
    facts["diagnostics"] = []
    if not facts["kqueue_available"]:
        facts["diagnostics"].append("kqueue interface unavailable")
    if facts["system"] != "FreeBSD":
        facts["diagnostics"].append("not running on FreeBSD")
    sys.stdout.write(encode_json(facts, pretty=True) + "\n")
    return 0


def command_generate(args):
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        watched = root / "target"
        watched.write_text("initial", encoding="utf-8")
        sink = ConsoleSink(quiet=True)
        with KqueueEngine(sink, timeout=0.1) as engine:
            add_vnode(engine, watched)
            events = []
            for index in range(args.iterations):
                watched.write_text(f"iteration:{index}\n", encoding="utf-8")
                events.extend(engine.poll(0.1))
                if args.delay:
                    time.sleep(args.delay)
            result = {"iterations": args.iterations,
                      "events": [record.as_dict() for record in events],
                      "summary": engine.summary()}
    if args.output:
        atomic_write(args.output, encode_json(result, pretty=True) + "\n")
    else:
        sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0


def extend_parser(parser):
    sub = next(action for action in parser._actions
               if isinstance(action, argparse._SubParsersAction))
    profile = sub.add_parser("profile", help="advanced event timeline and anomaly analysis")
    profile.add_argument("path")
    profile.add_argument("--kind", action="append")
    profile.add_argument("--severity", action="append")
    profile.add_argument("--source", action="append")
    profile.add_argument("--start-ms", type=float)
    profile.add_argument("--end-ms", type=float)
    profile.add_argument("--strict", action="store_true")
    profile.add_argument("--bucket-seconds", type=float, default=1.0)
    profile.add_argument("--correlation-ms", type=float, default=100.0)
    profile.add_argument("--anomaly-sigma", type=float, default=3.0)
    profile.add_argument("--output")
    profile.set_defaults(func=command_profile)
    listen = sub.add_parser("listen", help="trace a TCP listener and clients")
    listen.add_argument("--host", default="127.0.0.1")
    listen.add_argument("--port", type=nonnegative_int, default=9000)
    listen.add_argument("--backlog", type=positive_int, default=128)
    listen.add_argument("--echo", action="store_true")
    add_engine_arguments(listen)
    listen.set_defaults(func=command_listen)
    connect = sub.add_parser("connect", help="trace nonblocking TCP connection")
    connect.add_argument("host")
    connect.add_argument("port", type=positive_int)
    connect.add_argument("--timeout", type=float, default=5.0)
    connect.set_defaults(func=command_connect)
    udp = sub.add_parser("udp", help="trace UDP socket readability")
    udp.add_argument("--host", default="127.0.0.1")
    udp.add_argument("--port", type=nonnegative_int, default=9001)
    udp.add_argument("--batch", type=positive_int, default=128)
    udp.add_argument("--buffer-size", type=positive_int, default=65536)
    add_engine_arguments(udp)
    udp.set_defaults(func=command_udp)
    compare = sub.add_parser("compare", help="compare two event summaries")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--output")
    compare.set_defaults(func=command_compare)
    sysctl_parser = sub.add_parser("sysctl", help="capture kernel sysctl values")
    sysctl_parser.add_argument("names", nargs="*")
    sysctl_parser.add_argument("--output")
    sysctl_parser.set_defaults(func=command_sysctl)
    sysctl_diff = sub.add_parser("sysctl-diff", help="compare kernel sysctl snapshots")
    sysctl_diff.add_argument("before")
    sysctl_diff.add_argument("after")
    sysctl_diff.set_defaults(func=command_sysctl_diff)
    limits = sub.add_parser("limits", help="inspect process resource limits")
    limits.set_defaults(func=command_limits)
    health = sub.add_parser("health", help="inspect FreeBSD host security context")
    health.set_defaults(func=command_health)
    generate = sub.add_parser("generate", help="generate controlled vnode events")
    generate.add_argument("--iterations", type=positive_int, default=10)
    generate.add_argument("--delay", type=float, default=0.01)
    generate.add_argument("--output")
    generate.set_defaults(func=command_generate)
    return parser


def inspect_open_files(pid):
    if platform.system() != "FreeBSD":
        return {"pid": pid, "supported": False}
    if shutil.which("procstat") is None:
        return {"pid": pid, "supported": False, "reason": "procstat unavailable"}
    files = safe_command(["procstat", "-f", str(pid)], 5)
    threads = safe_command(["procstat", "-t", str(pid)], 5)
    credentials = safe_command(["procstat", "-c", str(pid)], 5)
    return {"pid": pid, "supported": True, "files": files,
            "threads": threads, "credentials": credentials}


def command_fds(args):
    result = {"timestamp": timestamp(),
              "processes": [inspect_open_files(pid) for pid in args.pids]}
    if args.output:
        atomic_write(args.output, encode_json(result, pretty=True) + "\n")
    else:
        sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0


def inspect_kqueue_descriptors(pid):
    report = inspect_open_files(pid)
    files = report.get("files", {})
    output = files.get("stdout", "")
    matches = []
    for line in output.splitlines():
        if "kqueue" in line.lower() or "eventfd" in line.lower():
            matches.append(line.strip())
    return {"pid": pid, "descriptors": matches,
            "count": len(matches), "source": "procstat -f"}


def command_kqueues(args):
    result = {"timestamp": timestamp(),
              "processes": [inspect_kqueue_descriptors(pid) for pid in args.pids]}
    sys.stdout.write(encode_json(result, pretty=True) + "\n")
    return 0


def extend_diagnostics(parser):
    sub = next(action for action in parser._actions
               if isinstance(action, argparse._SubParsersAction))
    fds = sub.add_parser("fds", help="inspect FreeBSD process file descriptors")
    fds.add_argument("pids", nargs="+", type=positive_int)
    fds.add_argument("--output")
    fds.set_defaults(func=command_fds)
    kqueues = sub.add_parser("kqueues", help="find kqueue descriptors via procstat")
    kqueues.add_argument("pids", nargs="+", type=positive_int)
    kqueues.set_defaults(func=command_kqueues)
    return parser


def main(argv=None):
    parser = build_parser()
    extend_parser(parser)
    extend_diagnostics(parser)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ForensicsError, OSError, ValueError, KeyboardInterrupt) as exc:
        sys.stderr.write(f"{APP_NAME}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
