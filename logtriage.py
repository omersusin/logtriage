#!/data/data/com.termux/files/usr/bin/python3
"""logtriage — on-device Android incident triage.

Captures and classifies what actually breaks a rooted phone, then retraces
R8/ProGuard stack traces with a mapping.txt so obfuscated crashes become
readable. Pure stdlib: no pip, no build step, runs on Termux.

Subcommands
    capture            collect logcat/audio/thermal/dmesg into a timestamped dir
    analyze PATH...    classify incidents in log files, dirs, or stdin
    retrace FILE -m M  retrace a stack trace with an R8/ProGuard mapping.txt
    watch              follow logcat live, print findings as they happen

Exit codes: 0 = clean, 1 = findings, 2 = usage/IO error.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# logcat parsing
# --------------------------------------------------------------------------

# `MM-DD HH:MM:SS.mmm  PID  TID L TAG: message`  (-v threadtime, the default
# for `logcat -b all -v threadtime`, which is what ses-yakala.sh captures)
THREADTIME = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEFAS])\s+"
    r"(?P<tag>[^:]*?):\s?(?P<msg>.*)$"
)
# `MM-DD HH:MM:SS.mmm  PID  TID E TAG: message` (brief adds a space)
THREADTIME_BRIEF = re.compile(
    r"^(?P<ts>\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEFAS])\s+\S+\s+"
    r"(?P<tag>[^:]*?):\s?(?P<msg>.*)$"
)

# `at com.foo.Bar.baz(Bar.kt:42)` / `at a.b.c.a(:1)` / `at a.b.c.a(Unknown Source)`
FRAME = re.compile(
    r"^\s*at\s+(?P<cls>[\w$.]+)\.(?P<method>[\w$<>]+)"
    r"\((?P<loc>[^)]*)\)\s*$"
)
# `Caused by: x.y.Z: msg` and `Suppressed:`
CAUSE = re.compile(r"^\s*(?:Caused by|Suppressed):\s+(?P<cls>[\w$.]+)(?::\s?(?P<msg>.*))?$")


def parse_logcat_line(line: str) -> dict | None:
    """Parse one threadtime logcat line into a dict, or None if not a log line."""
    for rx in (THREADTIME, THREADTIME_BRIEF):
        m = rx.match(line)
        if m:
            d = m.groupdict()
            d["tag"] = d["tag"].strip()
            return d
    return None


@dataclass
class Frame:
    raw: str
    cls: str
    method: str
    loc: str = ""

    @property
    def line_no(self) -> int | None:
        m = re.search(r":(\d+)\)?$", self.loc)
        return int(m.group(1)) if m else None

    @property
    def file(self) -> str | None:
        m = re.match(r"^([\w$.]+\.(?:kt|java|scala))(?::\d+)?$", self.loc)
        return m.group(1) if m else None

    def __str__(self) -> str:
        return f"{self.cls}.{self.method}({self.loc})"


@dataclass
class Event:
    kind: str                      # crash|anr|lmkd|audio|thermal|leak
    severity: str                  # critical|high|medium|low
    title: str
    detail: str = ""
    frames: list[Frame] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)
    ts: str = ""
    pid: str = ""
    source: str = ""


# --- detectors ------------------------------------------------------------

RE_FATAL = re.compile(r"FATAL EXCEPTION:\s*(?P<thread>[\w\-/]+)?")
RE_ANR = re.compile(r"\bANR in (?P<pkg>[\w.]+)")
RE_LMKD = re.compile(r"(?:lowmemorykiller|lmkd):\s*Kill\s+'(?P<name>[^']+)'\s*\((?P<pid>\d+)")
RE_AUDIO = re.compile(
    r"(?P<what>underrun|xrun|glitch|overrun|write blocked for|"
    r"AudioTrack.*(?:error|fail)|AudioFlinger.*(?:error|fail)|"
    r"audio_hw_primary.*(?:error|fail)|AAudioStream.*(?:error|fail))",
    re.I,
)
RE_THERMAL = re.compile(
    r"(?:Thermal\s+status|thermal\s+mitigation|throttl(?:e|ing)|"
    r"temperature.*(?:exceed|high|critical))", re.I
)
RE_LEAK = re.compile(r"\b(OutOfMemoryError|GC overhead limit exceeded|"
                     r"Failed to allocate|lowmemorykiller)\b", re.I)
RE_ANR_REASON = re.compile(r"^\s*Reason:\s*(?P<reason>.+)$")
RE_ANR_BLOCK = re.compile(r"Blocked in handler on (?P<h>.+?) \(.*\) running on")


def _frames(lines: list[str]) -> list[Frame]:
    out = []
    for ln in lines:
        m = FRAME.match(ln)
        if m:
            out.append(Frame(ln, m["cls"], m["method"], m["loc"]))
    return out


RE_CRASH_HEADER = re.compile(
    r"^\s*(?:Process:\s|Cmd line:\s|Abort message:\s|--->\s|"
    r"[\w$]+(?:\.[\w$]+)*(?:Exception|Error|Throwable)(?::|\s*$))"
)


def _is_crash_body(st: str) -> bool:
    """Frames and causes always belong to the block."""
    return bool(FRAME.match(st) or CAUSE.match(st))


def _is_crash_header(st: str) -> bool:
    """Prologue lines: Process:, Cmd line:, Abort message:, the exception line."""
    return bool(RE_CRASH_HEADER.match(st))


# Backstop only — the header whitelist is the real rule.
_PROLOGUE_MAX = 8


def _scan_crash_block(lines: list[str], i: int) -> tuple[list[str], int]:
    """Consume one crash block. Returns (body_lines, next_index).

    The prologue (Process:/Cmd line:/exception message) is consumed until the
    first frame or cause appears; from then on anything that is not a frame or
    a cause ends the block. Without this a crash at the top of a concatenated
    log swallows every unrelated event after it.

    The prologue is capped at _PROLOGUE_MAX lines: a real crash prints a
    handful of header lines, so a long run of non-frame lines means we are
    actually looking at a new entry — or at a FATAL with no stack at all.
    """
    block: list[str] = []
    seen_body = False
    prologue = 0
    j = i + 1
    while j < len(lines):
        nxt = lines[j]
        nm = parse_logcat_line(nxt)
        nmsg = nm["msg"] if nm else nxt
        if nm is None and nxt.startswith("--------- beginning of"):
            break
        if RE_FATAL.search(nmsg):
            break
        st = nmsg.strip()
        if _is_crash_body(st):
            seen_body = True
            block.append(nmsg)
            j += 1
            continue
        if seen_body or not st:
            break                       # stack is over, or a blank separator
        if prologue >= _PROLOGUE_MAX or not _is_crash_header(st):
            break                       # not a crash header — new entry
        block.append(nmsg)              # still in the prologue
        prologue += 1
        j += 1
    return block, j


RE_ANR_KEYWORD = re.compile(
    r"^\s*(?:Reason:|Load:|CPU usage|Blocked in handler|ANR in|"
    r"Broadcast of Intent|Force stopping|Subject:|Load average|CPU: )"
)


def _scan_anr_block(lines: list[str], i: int) -> tuple[list[str], int]:
    """Consume one ANR block.

    `logcat -d` emits no blank-line separators between entries, so we cannot
    rely on a blank line to end the block. We take the continuation lines that
    belong to the ANR report — same reporting pid, or a recognised ANR
    keyword — and stop at the first unrelated entry.
    """
    meta0 = parse_logcat_line(lines[i]) or {}
    pid0 = meta0.get("pid")
    block: list[str] = []
    j = i + 1
    while j < len(lines) and j < i + 80:
        nxt = lines[j]
        nm = parse_logcat_line(nxt)
        nmsg = nm["msg"] if nm else nxt
        if nm is None and nxt.startswith("--------- beginning of") and j > i + 2:
            break
        if not nmsg.strip():
            break
        if nm is not None and pid0 is not None and nm["pid"] != pid0 \
                and not RE_ANR_KEYWORD.match(nmsg):
            break                      # unrelated entry — do not swallow it
        block.append(nxt)
        j += 1
    return block, j


def scan(text: str, source: str = "") -> list[Event]:
    """Scan log text, return classified events.

    Crashes and ANRs are collected as blocks (from trigger to the end of the
    contiguous stack). Everything else is per-line.
    """
    events: list[Event] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        meta = parse_logcat_line(ln)
        msg = meta["msg"] if meta else ln
        ts = meta["ts"] if meta else ""
        pid = meta["pid"] if meta else ""
        tag = meta["tag"] if meta else ""

        # ---- crash block -------------------------------------------------
        m = RE_FATAL.search(msg)
        if m:
            block, i = _scan_crash_block(lines, i)
            causes = []
            for b in block:
                cm = CAUSE.match(b)
                if cm:
                    causes.append(f"{cm['cls']}: {cm['msg'] or ''}".strip())
            exc = next((b for b in block if "Exception" in b or "Error" in b), "")
            events.append(Event(
                kind="crash", severity="critical",
                title=f"Uncaught exception in thread '{m['thread'] or '?'}'"
                      + (f" [{tag}]" if tag else ""),
                detail=exc.strip(),
                frames=_frames(block),
                causes=causes, ts=ts, pid=pid, source=source,
            ))
            continue

        # ---- ANR block ---------------------------------------------------
        m = RE_ANR.search(msg)
        if m:
            block, i = _scan_anr_block(lines, i)
            reason = ""
            for b in block:
                rr = RE_ANR_REASON.match(b) or RE_ANR_REASON.match(
                    (parse_logcat_line(b) or {}).get("msg", ""))
                if rr:
                    reason = rr["reason"].strip()
                    break
            blocker = next((b for b in block if RE_ANR_BLOCK.search(b)), "")
            events.append(Event(
                kind="anr", severity="critical",
                title=f"ANR in {m['pkg']}" + (f" — {reason}" if reason else ""),
                detail=(RE_ANR_BLOCK.search(blocker).group("h") if blocker else ""),
                frames=_frames(block), ts=ts, pid=pid, source=source,
            ))
            continue

        # ---- low-memory kill ---------------------------------------------
        m = RE_LMKD.search(ln)
        if m:
            events.append(Event(
                kind="lmkd", severity="high",
                title=f"Process killed by lowmemorykiller: {m['name']} (pid {m['pid']})",
                detail=ln.strip(), ts=ts, pid=m["pid"], source=source,
            ))
            i += 1
            continue

        # ---- audio glitch ------------------------------------------------
        m = RE_AUDIO.search(ln)
        if m:
            sev = "high" if re.search(r"underrun|xrun|glitch", m.group(0), re.I) else "medium"
            events.append(Event(
                kind="audio", severity=sev,
                title=f"Audio: {m.group(0).strip()}",
                detail=ln.strip(), ts=ts, pid=pid, source=source,
            ))
            i += 1
            continue

        # ---- thermal -----------------------------------------------------
        if RE_THERMAL.search(ln):
            events.append(Event(
                kind="thermal", severity="medium",
                title="Thermal event", detail=ln.strip(),
                ts=ts, pid=pid, source=source,
            ))
            i += 1
            continue

        # ---- memory exhaustion -------------------------------------------
        if re.search(r"java\.lang\.OutOfMemoryError|GC overhead limit exceeded", ln):
            events.append(Event(
                kind="leak", severity="high", title="Memory exhaustion",
                detail=ln.strip(), ts=ts, pid=pid, source=source,
            ))
            i += 1
            continue

        i += 1
    return events


# --------------------------------------------------------------------------
# R8 / ProGuard retrace
# --------------------------------------------------------------------------

RE_MAPPING_CLASS = re.compile(r"^(?P<orig>[\w$.]+)\s*->\s*(?P<obf>[\w$.]+):\s*$")
RE_MAPPING_METHOD = re.compile(
    r"^\s+(?:(?P<sline>\d+):(?P<eline>\d+):)?"
    r"(?P<ret>[\w$.<>]+)\s+(?P<name>[\w$<>]+)\((?P<args>.*?)\)"
    r"(?::(?P<oline>\d+)(?::(?P<oend>\d+))?)?"
    r"\s*->\s*(?P<obf>[\w$<>]+)\s*$"
)
RE_MAPPING_FIELD = re.compile(
    r"^\s+(?P<type>[\w$.<>]+)\s+(?P<name>[\w$<>]+)\s*->\s*(?P<obf>[\w$<>]+)\s*$"
)


@dataclass
class MethodMapping:
    obf: str
    orig_name: str
    orig_class: str
    sline: int | None = None
    eline: int | None = None
    oline: int | None = None
    oend: int | None = None


class Retracer:
    """Minimal R8/ProGuard mapping.txt retracer.

    Handles the parts that matter in practice: class renaming, method
    renaming, and line-number recovery when the obfuscated line falls inside a
    mapped original range. Frames it cannot resolve are returned unchanged
    rather than guessed at.
    """

    def __init__(self, mapping_text: str | None = None):
        self.classes: dict[str, str] = {}        # obf class -> orig class
        self.methods: dict[str, dict[str, list[MethodMapping]]] = {}  # obf cls -> obf m -> [...]
        self.fields: dict[str, dict[str, str]] = {}
        if mapping_text:
            self.load(mapping_text)

    def load(self, text: str) -> "Retracer":
        cur_obf = None
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            mc = RE_MAPPING_CLASS.match(raw)
            if mc and not raw.startswith(" "):
                cur_obf = mc["obf"]
                self.classes[cur_obf] = mc["orig"]
                self.methods.setdefault(cur_obf, {})
                self.fields.setdefault(cur_obf, {})
                continue
            if cur_obf is None:
                continue
            mm = RE_MAPPING_METHOD.match(raw)
            if mm:
                self.methods[cur_obf].setdefault(mm["obf"], []).append(MethodMapping(
                    obf=mm["obf"], orig_name=mm["name"], orig_class=self.classes[cur_obf],
                    sline=int(mm["sline"]) if mm["sline"] else None,
                    eline=int(mm["eline"]) if mm["eline"] else None,
                    oline=int(mm["oline"]) if mm["oline"] else None,
                    oend=int(mm["oend"]) if mm["oend"] else None,
                ))
                continue
            mf = RE_MAPPING_FIELD.match(raw)
            if mf:
                self.fields[cur_obf][mf["obf"]] = mf["name"]
        return self

    def retrace_frame(self, fr: Frame) -> tuple[str, bool]:
        """Return (rendered_frame, was_resolved)."""
        cls = self.classes.get(fr.cls)
        if cls is None:
            return str(fr), False           # not obfuscated: leave as-is
        cands = self.methods.get(fr.cls, {}).get(fr.method, [])
        if not cands:
            return f"{cls}.{fr.method}({fr.loc})", True
        ln = fr.line_no
        best = None
        if ln is not None:
            for c in cands:
                if c.sline is not None and c.oline is not None and c.sline <= ln:
                    # prefer the tightest range that still contains the line
                    span = (c.eline - c.sline) if c.eline is not None else (1 << 30)
                    if best is None or span < best[0]:
                        best = (span, c)
            if best is None:
                for c in cands:
                    if c.oline is not None:
                        best = (1 << 30, c)
                        break
        elif len(cands) == 1:
            best = (0, cands[0])
        if best is None:
            # No candidate carried usable line info — common when R8 is built
            # with line-number stripping. If the name is unambiguous we can
            # still recover the method; the obfuscated line is then meaningless
            # so we do not print it.
            names = {c.orig_name for c in cands}
            if len(names) == 1:
                c = cands[0]
                return f"{c.orig_class}.{c.orig_name}(SourceFile)", True
            return f"{cls}.<{', '.join(sorted(names))}>({fr.loc})", True
        c = best[1]
        oline = c.oline
        if oline is not None and c.sline is not None and ln is not None:
            oline = c.oline + (ln - c.sline)      # rebase the line number
        loc = f"SourceFile:{oline}" if oline is not None else "SourceFile"
        return f"{c.orig_class}.{c.orig_name}({loc})", True


def retrace_text(text: str, retracer: Retracer) -> str:
    out = []
    for ln in text.splitlines():
        m = FRAME.match(ln)
        if m:
            fr = Frame(ln, m["cls"], m["method"], m["loc"])
            new, _ = retracer.retrace_frame(fr)
            indent = ln[:len(ln) - len(ln.lstrip())]
            out.append(f"{indent}at {new}")
        else:
            out.append(ln)
    return "\n".join(out)


# --------------------------------------------------------------------------
# capture
# --------------------------------------------------------------------------

def run(cmd: list[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return ""


# A root manager (KernelSU / Magisk / APatch) may gate the first su request.
# If we time out before it is answered we must not silently look "unrooted" -
# that reads as a bug. 60s leaves room to actually approve it.
ROOT_TIMEOUT = 60

# PATH alone is not enough to find su: a bare interactive `su` needs no help,
# but an app spawning su from a restricted environment can have a minimal PATH
# while the binary still exists on disk.
SU_CANDIDATES = ("/system/bin/su", "/system/xbin/su", "/debug_ramdisk/su",
                 "/sbin/su", "/data/adb/magisk/su")


def find_su() -> str | None:
    """Locate su on PATH, then at the usual root-manager/system locations."""
    found = shutil.which("su")
    if found:
        return found
    for cand in SU_CANDIDATES:
        try:
            if Path(cand).exists():
                return cand
        except OSError:
            continue
    return None


# Root implementations, keyed by the on-disk marker each one drops in /data/adb.
# Sources: kernelsu.org/guide, apatch.dev/faq.
ROOT_DIRS = {
    "/data/adb/ksu": "KernelSU",
    "/data/adb/magisk": "Magisk",
    "/data/adb/ap": "APatch",
    "/data/adb/kp": "KernelPatch",
}
# The SELinux domain is the most reliable fingerprint: it is set by the root
# solution itself, not by whatever shell happens to invoke su.
#   u:r:ksu:s0     KernelSU
#   u:r:magisk:s0  Magisk
#   u:r:su:s0      ambiguous - KernelPatch/APatch, or KernelSU-Next
SELINUX_FINGERPRINT = {
    "ksu": "KernelSU",
    "magisk": "Magisk",
    "su": "KernelPatch/APatch or KernelSU-Next (ambiguous domain u:r:su:s0)",
    "init": "unknown (fell back to u:r:init:s0)",
}
RE_SELINUX_CTX = re.compile(r"context=u:r:([\w]+):s\d")


def detect_root_impl(su: str) -> tuple[str, str]:
    """Identify which root solution is in use. Returns (name, evidence).

    Probes three independent signals, because any one of them can lie:
      1. the SELinux domain from `id` - set by the root implementation itself
      2. marker directories under /data/adb - KernelSU hides these from apps it
         has not permitted, so absence proves nothing
      3. version banners: KernelSU exports KSU_VER, Magisk answers `magisk -V`
    """
    evidence: list[str] = []

    idout = run([su, "-c", "id"], timeout=25)
    ctx = RE_SELINUX_CTX.search(idout)
    if ctx:
        evidence.append("selinux=u:r:%s:s0" % ctx.group(1))

    listing = run([su, "-c", "ls -d /data/adb/*/ 2>/dev/null"], timeout=25)
    found = {name for path, name in ROOT_DIRS.items() if path in listing}
    if found:
        evidence.append("markers=" + "+".join(sorted(found)))

    for label, cmd, rx in (
        ("KernelSU", "echo ${KSU_VER:-}", r"v[\w.\-]+"),
        ("Magisk", "magisk -V 2>/dev/null", r"[\d.]+"),
        ("APatch", "echo ${APATCH_VERSION:-}${KP_VERSION:-}", r"[\w.\-]+"),
    ):
        out = run([su, "-c", cmd], timeout=25).strip()
        if out and re.search(rx, out):
            evidence.append("%s=%s" % (label, out.splitlines()[0][:24]))

    name = ""
    if ctx and ctx.group(1) in ("ksu", "magisk"):
        name = SELINUX_FINGERPRINT[ctx.group(1)]
    elif found:
        name = sorted(found)[0]
    elif ctx:
        name = SELINUX_FINGERPRINT.get(ctx.group(1), ctx.group(1))
    if not name:
        name = "unknown root implementation"

    return name, ", ".join(evidence) if evidence else "no identifying signal"


def probe_root() -> tuple[bool, str]:
    """Return (is_root, human-readable reason).

    The reason matters more than the boolean. "Not rooted", "Termux not on the
    root manager allowlist", "denied", and "you never approved the prompt" all
    fail identically but need completely different fixes.
    """
    su = find_su()
    if not su:
        return False, ("no `su` visible to Termux. Two very different causes: "
                       "the device is not rooted, OR Termux is not on the root "
                       "manager allowlist. KernelSU deliberately hides su from "
                       "every app it has not permitted, so a missing su does NOT "
                       "mean no root. Open the root manager and allow Termux, "
                       "then re-run `logtriage doctor`.")
    try:
        proc = subprocess.run([su, "-c", "id"], capture_output=True,
                              text=True, timeout=ROOT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, ("`%s` gave no answer within %ds - the root request was "
                       "probably never approved. Run `logtriage doctor` and "
                       "allow it." % (su, ROOT_TIMEOUT))
    except OSError as e:
        return False, "`%s` could not be executed: %s" % (su, e)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if "uid=0" in out:
        return True, "root OK via %s" % su
    if proc.returncode != 0:
        return False, ("`%s` refused (exit %d): %s - check your root manager, "
                       "Termux must be on the allowlist"
                       % (su, proc.returncode, out[:140] or "no output"))
    return False, "`%s` ran but was not uid=0: %s" % (su, out[:140])


def has_root() -> bool:
    return probe_root()[0]


def capture_root() -> Path:
    """Where captures go.

    Internal storage by default: logs are the one artefact you actually want to
    open in a file manager, pull over adb, or read from another app, and
    /sdcard survives a Termux reinstall. Falls back to $HOME if sdcard is not
    writable. Kept inside the project dir but gitignored, so a 4 MB logcat dump
    never reaches a commit.
    """
    # `.parent`, not `.resolve()`: /sdcard is a symlink to /storage/emulated/0,
    # and resolving it makes every printed path longer than what you typed.
    here = Path(__file__).parent
    for cand in (here / "captures", Path.home() / "logtriage-captures"):
        try:
            cand.mkdir(parents=True, exist_ok=True)
            probe = cand / ".wtest"
            probe.touch()
            probe.unlink()
            return cand
        except OSError:
            continue
    return Path.home() / "logtriage-captures"


def capture(outdir: Path | None = None, follow: bool = False) -> int:
    d = outdir or capture_root() / time.strftime("%m%d-%H%M%S")
    d.mkdir(parents=True, exist_ok=True)
    print(f"logtriage: capturing -> {d}", file=sys.stderr)

    if find_su():
        print("logtriage: requesting root — approve the prompt if your root "
              "manager shows one (KernelSU/Magisk may grant silently once "
              "Termux is allowed).", file=sys.stderr)

    rooted, why = probe_root()
    if rooted:
        print(f"logtriage: {why}", file=sys.stderr)
        run(["su", "-c", "logcat -c"], timeout=20)
        cmds = {
            "logcat.txt": "logcat -b all -v threadtime -d",
            "crash.txt": "logcat -b crash -d -v threadtime",
            "audio_flinger.txt": "dumpsys media.audio_flinger",
            "audio.txt": "dumpsys audio",
            "thermal.txt": "dumpsys thermalservice",
            "anr.txt": "cat /data/anr/traces.txt",
            "dmesg.txt": "dmesg",
        }
        for name, c in cmds.items():
            print(f"  - {name}", file=sys.stderr)
            (d / name).write_text(run(["su", "-c", c], timeout=90), errors="replace")
    else:
        print(f"logtriage: NOT rooted — {why}", file=sys.stderr)
        print("logtriage: falling back to plain `logcat -d`. Only logcat.txt "
              "will be captured (no audio_flinger, thermal, ANR or dmesg).",
              file=sys.stderr)
        (d / "logcat.txt").write_text(
            run(["logcat", "-b", "all", "-v", "threadtime", "-d"], timeout=90),
            errors="replace")

    if has_root():
        for anr in Path("/data/anr").glob("traces*"):
            try:
                (d / f"anr-{anr.name}.txt").write_text(
                    run(["su", "-c", f"cat {anr}"], timeout=60), errors="replace")
            except OSError:
                pass

    print(f"logtriage: done — analyze with: logtriage analyze {d}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
KIND_LABEL = {
    "crash": "CRASH", "anr": "ANR", "lmkd": "LOW-MEM", "leak": "OOM",
    "audio": "AUDIO", "thermal": "THERMAL",
}


def iter_texts(paths: list[str]):
    for p in paths:
        if p == "-":
            yield "<stdin>", sys.stdin.read()
            continue
        path = Path(p)
        if path.is_dir():
            for f in sorted(path.rglob("*")):
                if f.is_file() and f.suffix in ("", ".txt", ".log"):
                    try:
                        yield str(f), f.read_text(errors="replace")
                    except OSError:
                        continue
        elif path.is_file():
            try:
                yield str(path), path.read_text(errors="replace")
            except OSError:
                continue
        else:
            print(f"logtriage: no such path: {p}", file=sys.stderr)


def render(events: list[Event], retracer: Retracer | None, top: int) -> str:
    if not events:
        return "No incidents found. Clean."
    counts: dict[str, int] = {}
    for e in events:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    order = sorted(counts.items(), key=lambda kv: -kv[1])
    out = ["=" * 68, "logtriage report", "=" * 68]
    out.append("  " + "   ".join(f"{KIND_LABEL.get(k, k)}={v}" for k, v in order))
    out.append("")

    ranked = sorted(events, key=lambda e: SEV_ORDER.get(e.severity, 9))
    for e in ranked[:top]:
        head = f"[{e.severity.upper()}] {KIND_LABEL.get(e.kind, e.kind)}  {e.title}"
        out.append(head)
        if e.ts:
            out.append(f"    when    : {e.ts}")
        if e.pid:
            out.append(f"    pid     : {e.pid}")
        if e.source:
            out.append(f"    source  : {e.source}")
        if e.detail:
            out.append(f"    detail  : {e.detail[:300]}")
        for c in e.causes:
            out.append(f"    caused  : {c[:200]}")
        if e.frames:
            out.append(f"    stack   : {len(e.frames)} frames")
            shown = e.frames[:12]
            if retracer:
                shown = [retracer.retrace_frame(f)[0] for f in shown]
            for f in shown:
                out.append(f"        at {f}")
            if len(e.frames) > len(shown):
                out.append(f"        ... {len(e.frames) - len(shown)} more")
        out.append("")
    if len(ranked) > top:
        out.append(f"... {len(ranked) - top} more findings (use --top to see more)")
    return "\n".join(out)


# --------------------------------------------------------------------------
# watch
# --------------------------------------------------------------------------

def watch(interval: float, retracer: Retracer | None) -> int:
    if not has_root():
        print("logtriage watch: needs root for full logcat buffers", file=sys.stderr)
    cmd = ["su", "-c", "logcat -b all -v threadtime -T 1"] if has_root() \
        else ["logcat", "-b", "all", "-v", "threadtime", "-T", "1"]
    print("logtriage: following logcat — Ctrl+C to stop", file=sys.stderr)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, bufsize=1)
    except FileNotFoundError:
        print("logtriage watch: logcat not found", file=sys.stderr)
        return 2
    buf: list[str] = []
    try:
        assert proc.stdout
        for line in proc.stdout:
            buf.append(line)
            # flush on a quiet moment so crash blocks stay contiguous
            if not line.strip():
                ev = scan("".join(buf))
                for e in ev:
                    if e.severity in ("critical", "high"):
                        print(f"\n!! [{e.severity.upper()}] {e.title}")
                        if e.detail:
                            print(f"   {e.detail[:200]}")
                        for f in e.frames[:6]:
                            shown = retracer.retrace_frame(f)[0] if retracer else str(f)
                            print(f"     at {shown}")
                buf.clear()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
    return 0


# --------------------------------------------------------------------------

def doctor() -> int:
    print("logtriage doctor")
    print("-" * 60)
    print(f"python       : {sys.version.split()[0]}  ({sys.executable})")
    print(f"script       : {Path(__file__).parent}")

    sd = Path("/sdcard")
    try:
        root_dir = capture_root()
        probe = root_dir / ".wtest"
        probe.touch()
        probe.unlink()
        print(f"captures ->  : {root_dir}  (writable)")
    except OSError as e:
        print(f"captures ->  : PROBLEM — {e}")
    print(f"/sdcard      : {'present' if sd.exists() else 'MISSING'}")

    su = find_su()
    print(f"su on PATH   : {shutil.which('su') or 'not found'}")
    print(f"su on disk   : {su or 'not found in any known location'}")

    rooted, why = probe_root()
    print(f"su -c id     : {why}")

    if rooted and su:
        name, evidence = detect_root_impl(su)
        print(f"root impl    : {name}")
        print(f"evidence     : {evidence}")
        print()
        if name.startswith("KernelSU"):
            print("KernelSU notes:")
            print("  - grant is per-app in the KernelSU manager; su is invisible")
            print("    to any app it has not permitted, so a missing su means")
            print("    'not allowed', not 'not rooted'.")
            print("  - its BusyBox lives at /data/adb/ksu/bin/busybox")
            print("    (Magisk uses /data/adb/magisk/busybox)")
            print("  - modules get KSU=true and KSU_VER in the environment")
            print("  - no built-in Zygisk; uses ZygiskNext metamodule")
        elif name == "Magisk":
            print("Magisk notes:")
            print("  - manager: Magisk app -> Superuser -> Termux -> grant")
            print("  - BusyBox at /data/adb/magisk/busybox")
    else:
        print()
        print("Fixing a root refusal depends on the actual cause:")
        print("  - KernelSU: grant Termux in the KernelSU manager, then re-run.")
        print("    `no su` here usually means Termux is not on the allowlist.")
        print("  - Magisk: Magisk app -> Superuser -> Termux -> grant.")
        print("  - unrooted: no root manager installed; logtriage will still")
        print("    capture logcat, just not audio_flinger/thermal/ANR/dmesg.")

    print()
    print("Do NOT `su` first - that drops you into Android's /system/bin/sh with "
          "Android's PATH, and logtriage vanishes from the command line.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="logtriage", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture", help="collect logs into a timestamped directory")
    c.add_argument("-o", "--out", type=Path, default=None)

    d = sub.add_parser("doctor", help="report environment: root, sdcard, python")
    d.set_defaults(_noop=True)

    a = sub.add_parser("analyze", help="classify incidents in logs")
    a.add_argument("paths", nargs="+", help="files, dirs, or - for stdin")
    a.add_argument("-m", "--mapping", type=Path, default=None, help="R8/ProGuard mapping.txt")
    a.add_argument("--top", type=int, default=20, help="max findings to print")
    a.add_argument("--json", action="store_true", help="emit JSON")

    r = sub.add_parser("retrace", help="retrace a stack trace")
    r.add_argument("trace", help="file containing frames, or - for stdin")
    r.add_argument("-m", "--mapping", type=Path, required=True)

    w = sub.add_parser("watch", help="follow logcat live")
    w.add_argument("-m", "--mapping", type=Path, default=None)

    ns = ap.parse_args(argv)

    if ns.cmd == "doctor":
        return doctor()

    retracer: Retracer | None = None
    mp = getattr(ns, "mapping", None)
    if mp:
        try:
            retracer = Retracer(mp.read_text(errors="replace"))
        except OSError as e:
            print(f"logtriage: cannot read mapping: {e}", file=sys.stderr)
            return 2

    if ns.cmd == "capture":
        return capture(ns.out)

    if ns.cmd == "watch":
        return watch(1.0, retracer)

    if ns.cmd == "retrace":
        text = sys.stdin.read() if ns.trace == "-" else Path(ns.trace).read_text(errors="replace")
        print(retrace_text(text, retracer))
        return 0

    events: list[Event] = []
    for src, text in iter_texts(ns.paths):
        events.extend(scan(text, src))

    if ns.json:
        import json as _json
        print(_json.dumps([{
            "kind": e.kind, "severity": e.severity, "title": e.title,
            "detail": e.detail, "ts": e.ts, "pid": e.pid, "source": e.source,
            "causes": e.causes,
            "frames": [str(retracer.retrace_frame(f)[0]) if retracer else str(f)
                       for f in e.frames],
        } for e in sorted(events, key=lambda x: SEV_ORDER.get(x.severity, 9))], indent=2))
    else:
        print(render(events, retracer, ns.top))

    return 1 if events else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
