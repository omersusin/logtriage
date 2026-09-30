#!/usr/bin/env python3
"""Self-check for logtriage. Run: python3 test_logtriage.py

Covers the parsers and the retrace math. No framework, no fixtures on disk —
the log and mapping samples are inline so this stays one file.
"""
import sys

from logtriage import (FRAME, SELINUX_FINGERPRINT, Frame, RE_SELINUX_CTX,
                       Retracer, parse_logcat_line, retrace_text, scan)

FAILS: list[str] = []


def check(name: str, got, want) -> None:
    if got != want:
        FAILS.append(f"{name}\n     got:  {got!r}\n     want: {want!r}")


def check_true(name: str, cond) -> None:
    if not cond:
        FAILS.append(f"{name}\n     expected truthy, got {cond!r}")


# ---------------------------------------------------------------- logcat line
check("threadtime parse",
      parse_logcat_line(
          "09-26 23:30:00.581 11873 11873 E AndroidRuntime: FATAL EXCEPTION: main"),
      {"ts": "09-26 23:30:00.581", "pid": "11873", "tid": "11873",
       "level": "E", "tag": "AndroidRuntime",
       "msg": "FATAL EXCEPTION: main"})
check("non-log line is None",
      parse_logcat_line("--------- beginning of crash"), None)

# ------------------------------------------------------------------- crashes
CRASH = """\
09-26 23:30:00.581 11873 11873 E AndroidRuntime: FATAL EXCEPTION: main
09-26 23:30:00.581 11873 11873 E AndroidRuntime: Process: com.grabit.app, PID: 11873
09-26 23:30:00.582 11873 11873 E AndroidRuntime: java.lang.NullPointerException: Attempt to invoke virtual method 'android.webkit.WebSettings android.webkit.WebView.getSettings()' on a null object reference
09-26 23:30:00.582 11873 11873 E AndroidRuntime: \tat android.webkit.WebView.getSettings(WebView.java:1250)
09-26 23:30:00.582 11873 11873 E AndroidRuntime: \tat a.b.c.a(SourceFile:12)
09-26 23:30:00.583 11873 11873 E AndroidRuntime: Caused by: java.lang.IllegalStateException: closed
09-26 23:30:00.583 11873 11873 E AndroidRuntime: \tat a.b.c.b(SourceFile:44)
09-26 23:30:01.000 11873 11873 E AndroidRuntime: FATAL EXCEPTION: main
"""

ev = scan(CRASH)
check("crash count", len([e for e in ev if e.kind == "crash"]), 2)
c = [e for e in ev if e.kind == "crash"][0]
check("crash severity", c.severity, "critical")
check_true("crash has NPE detail", "NullPointerException" in c.detail)
check("crash frame count", len(c.frames), 3)
check("crash first frame class", c.frames[0].cls, "android.webkit.WebView")
check("crash cause recorded", len(c.causes), 1)
check_true("crash cause text", "IllegalStateException" in c.causes[0])

# ----------------------------------------------------------------------- ANR
ANR = """\
09-26 23:31:00.000 12000 12000 E ActivityManager: ANR in com.grabit.app
09-26 23:31:00.000 12000 12000 E ActivityManager: Reason: Input dispatching timed out
09-26 23:31:00.100 12000 12000 E ActivityManager: Blocked in handler on main thread (com.grabit.app) running on ActivityThread
"""
a = [e for e in scan(ANR) if e.kind == "anr"]
check("anr count", len(a), 1)
check("anr severity", a[0].severity, "critical")
check_true("anr reason captured", "Input dispatching" in a[0].title)

# ---------------------------------------------------------- lmkd / audio / thermal
MISC = """\
09-26 23:32:00.000     0     0 I lowmemorykiller: Kill 'com.grabit.app' (11873), adj 900, to free 51200kB
09-26 23:33:00.000 11873 11873 W AudioFlinger: underrun, frame count 0x100 active 0x80
09-26 23:33:10.000 11873 11873 E audio_hw_primary: write blocked for 220 msecs
09-26 23:34:00.000 11873 11873 I ThermalService: Thermal status: 3 (SEVERE)
09-26 23:35:00.000 11873 11873 E AndroidRuntime: java.lang.OutOfMemoryError: Failed to allocate a 12582912 byte allocation
"""
kinds = [e.kind for e in scan(MISC)]
check("lmkd detected", "lmkd" in kinds, True)
check("audio underrun detected", "audio" in kinds, True)
check("audio write-block detected", kinds.count("audio"), 2)
check("thermal detected", "thermal" in kinds, True)
check("oom detected", "leak" in kinds, True)

# -------------------------------------------------------------------- retrace
# Shaped like a real R8 mapping.txt produced by an AGP release build.
MAPPING = """\
# compiler: R8
# compiler_version: 8.9.27
com.grabit.app.ui.Web -> a.b.c:
    1:1:void <init>() -> <init>
    12:12:android.webkit.WebSettings getSettings() -> a
    20:24:void load(java.lang.String) -> b
    40:44:java.lang.String render():10:14 -> c
com.grabit.app.net.Downloader -> a.b.d:
    void enqueue(java.lang.String) -> a
"""
rt = Retracer(MAPPING)

check("class map size", len(rt.classes), 2)
check("obf class resolves", rt.classes.get("a.b.c"), "com.grabit.app.ui.Web")
check("obf method table", "a" in rt.methods["a.b.c"], True)

# R8 with line-number stripping: method name is recoverable, line is not.
fr = Frame("x", "a.b.c", "a", ":12")
rendered, ok = rt.retrace_frame(fr)
check_true("obf frame resolved", ok)
check("retraced name, no line info in mapping",
      rendered, "com.grabit.app.ui.Web.getSettings(SourceFile)")

# Line 999 is outside the mapped 12..12 range; name still resolves, and we
# deliberately do NOT invent a line number.
fr2 = Frame("x", "a.b.c", "a", ":999")
r2, _ = rt.retrace_frame(fr2)
check("out-of-range line resolves name only",
      r2, "com.grabit.app.ui.Web.getSettings(SourceFile)")

# Mapping that carries original line info -> rebase onto the obfuscated line.
# `40:44:... render():10:14` means obfuscated 40..44 == original 10..14, so
# obfuscated 42 lands on original 12.
fr5 = Frame("x", "a.b.c", "c", ":42")
r5, _ = rt.retrace_frame(fr5)
check("rebased original line", r5, "com.grabit.app.ui.Web.render(SourceFile:12)")

fr5b = Frame("x", "a.b.c", "c", ":41")
r5b, _ = rt.retrace_frame(fr5b)
check("rebased off-by-one line", r5b, "com.grabit.app.ui.Web.render(SourceFile:11)")

fr5c = Frame("x", "a.b.c", "c", ":44")
r5c, _ = rt.retrace_frame(fr5c)
check("rebased range end", r5c, "com.grabit.app.ui.Web.render(SourceFile:14)")

# unknown obfuscated method -> class resolved, method left alone
fr3 = Frame("x", "a.b.c", "zzz", ":5")
r3, _ = rt.retrace_frame(fr3)
check("unknown obf method", r3, "com.grabit.app.ui.Web.zzz(:5)")

# non-obfuscated frame passes through untouched
fr4 = Frame("x", "android.webkit.WebView", "getSettings", "WebView.java:1250")
r4, ok4 = rt.retrace_frame(fr4)
check("library frame untouched", str(fr4), r4)
check("library frame not marked resolved", ok4, False)

# full-text retrace keeps indentation and non-frame lines
TRACE = """\
Caused by: java.lang.IllegalStateException: closed
\tat a.b.c.a(SourceFile:12)
\tat android.webkit.WebView.getSettings(WebView.java:1250)
"""
out = retrace_text(TRACE, rt)
check_true("retrace keeps 'Caused by'", "Caused by:" in out)
check_true("retrace indents obf frame",
           "\tat com.grabit.app.ui.Web.getSettings(SourceFile)" in out)
check_true("retrace leaves lib frame",
           "at android.webkit.WebView.getSettings(WebView.java:1250)" in out)

# ----------------------------------------------------------------------- frame
m = FRAME.match("\tat com.foo.Bar.baz(Bar.kt:42)")
check("frame regex", (m["cls"], m["method"], m["loc"]), ("com.foo.Bar", "baz", "Bar.kt:42"))

# ---------------------------------------------------------------------- empty
check("clean log yields nothing", scan("09-26 23:36:00.000 1 1 I Tag: fine"), [])

# ------------------------------------------------- regression: block greediness
# `logcat -d` emits NO blank-line separators, so a crash or ANR block must not
# swallow the unrelated events that follow it. This caught CRASH=1 and nothing
# else being reported from a mixed log.
MIXED = CRASH + """\
09-26 23:31:00.000 12000 12000 E ActivityManager: ANR in com.grabit.app
09-26 23:31:00.000 12000 12000 E ActivityManager: Reason: Input dispatching timed out
09-26 23:32:00.000     0     0 I lowmemorykiller: Kill 'com.grabit.app' (11873), adj 900
09-26 23:33:00.000 11873 11873 W AudioFlinger: underrun, frame count 0x100
09-26 23:34:00.000 11873 11873 I ThermalService: Thermal status: 3 (SEVERE)
"""
mx = scan(MIXED)
mx_kinds = [e.kind for e in mx]
check("mixed: crash found", mx_kinds.count("crash"), 2)
check("mixed: anr found", mx_kinds.count("anr"), 1)
check("mixed: lmkd found", mx_kinds.count("lmkd"), 1)
check("mixed: audio found", mx_kinds.count("audio"), 1)
check("mixed: thermal found", mx_kinds.count("thermal"), 1)
check_true("mixed: crash did not swallow the ANR",
           any(e.kind == "anr" for e in mx))
check_true("mixed: ANR did not swallow the lmkd",
           any(e.kind == "lmkd" for e in mx))
# the crash block must contain only its own frames
first_crash = [e for e in mx if e.kind == "crash"][0]
check("mixed: crash frame count unchanged", len(first_crash.frames), 3)

# ------------------------------------------------------------------------ run
if FAILS:
    print(f"FAIL — {len(FAILS)} check(s) failed\n")
    for f in FAILS:
        print("  x " + f)
    sys.exit(1)
print("PASS — all checks green")

# ------------------------------------------------- root-implementation detection
# The SELinux domain is the reliable fingerprint, and it is pure string work,
# so it is testable without root.
KSU_ID = ("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0")
MAGISK_ID = ("uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0")
APATCH_ID = ("uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0")

check("ksu domain parsed", RE_SELINUX_CTX.search(KSU_ID).group(1), "ksu")
check("magisk domain parsed", RE_SELINUX_CTX.search(MAGISK_ID).group(1), "magisk")
check("apatch domain parsed", RE_SELINUX_CTX.search(APATCH_ID).group(1), "su")
check("no domain in plain id", RE_SELINUX_CTX.search("uid=0(root) gid=0(root)"), None)

check("ksu maps to KernelSU", SELINUX_FINGERPRINT["ksu"], "KernelSU")
check("magisk maps to Magisk", SELINUX_FINGERPRINT["magisk"], "Magisk")
check_true("su domain flagged ambiguous",
           "ambiguous" in SELINUX_FINGERPRINT["su"])
check_true("init domain flagged unknown",
           "unknown" in SELINUX_FINGERPRINT["init"])
