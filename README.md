# logtriage

On-device Android incident triage for rooted phones running Termux.

Captures what actually breaks a phone — crashes, ANRs, low-memory kills, audio
glitch, thermal throttle — and **retraces R8/ProGuard stack traces** so
minified crashes become readable again. Pure Python 3 stdlib: no pip, no build
step, no root required (root just widens what it can see).

## Why this exists

Every other logcat app is a *viewer*. You still scroll, still copy, still paste
into a search engine, still grep. The gap is turning a wall of text into a
verdict.

The nearest alternatives all stop at display: Logcat Reader (869★) colour-codes
and saves text; Crash Log Viewer extracts crash *types*; Android Studio's
Logcat needs a desktop. None parse `audio_flinger`, none look at `lmkd`, none
take a `mapping.txt`.

This is the bash version turned into a tool. `ses-yakala.sh` +
`ses-analiz.sh` already do the capture and the greps; logtriage does the
capture, the classification, the retracing, and the reporting.

## Where logs are saved

Captures land on internal storage, not in Termux's private `$HOME` — logs are
the one artefact you actually want to open in a file manager, pull over `adb`,
or read from another app:

```
/sdcard/logtriage/captures/<MMDD-HHMMSS>/
    logcat.txt  crash.txt  audio_flinger.txt  audio.txt
    thermal.txt anr.txt    dmesg.txt
```

They live *inside* the project dir so they travel with it, but `captures/` is
gitignored — a 3.7 MB logcat dump never reaches a commit. If `/sdcard` isn't
writable it falls back to `~/logtriage-captures/`.

Analyze a capture, or all of them:

```bash
logtriage analyze /sdcard/logtriage/captures/0930-200157
logtriage analyze /sdcard/logtriage/captures          # every capture
```

## Install

Kept on internal storage (`/sdcard/logtriage`) on purpose: `/sdcard` survives a
Termux reinstall, `$HOME` does not, and the tree stays browsable and
adb-accessible.

`sdcardfs` ignores `chmod`, so a script there can never carry the execute bit
and **cannot be exec'd directly** (`./logtriage.py` → Permission denied). A
wrapper in Termux home — where the execute bit does stick — supplies the
`logtriage` command:

```bash
# source of truth, on internal storage
cd /sdcard/logtriage && python3 test_logtriage.py

# wrapper (what you actually type)
mkdir -p ~/.local/bin
cat > ~/.local/bin/logtriage <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
exec python3 /sdcard/logtriage/logtriage.py "$@"
EOF
chmod +x ~/.local/bin/logtriage
```

No dependencies. Python 3.10+. Works unrooted; prompts for `su` only if it's
available.

## Do not `su` first

`su` with no arguments drops you into Android's `/system/bin/sh` with Android's
`PATH`, so `logtriage` (and Termux's Python) disappear from the command line:

```
~ $ su
:/data/data/com.termux/files/home # logtriage capture
/system/bin/sh: logtriage: inaccessible or not found
```

Run `logtriage capture` straight from the Termux prompt. It calls `su` itself
for the privileged parts and you approve the Magisk prompt once.

## Use

```bash
# capture a snapshot, then analyze it
logtriage capture
logtriage analyze ~/logtriage/<timestamp>

# analyze anything you already have, retracing with your build's mapping
logtriage analyze crash.txt -m ~/Sonara/app/build/outputs/mapping/release/mapping.txt

# live: prints critical/high findings as they happen
logtriage watch -m mapping.txt

# just retrace a pasted stack
pbpaste | logtriage retrace - -m mapping.txt

# machine-readable
logtriage analyze logs/ --json
```

**Exit codes:** `0` clean · `1` findings · `2` usage/IO error. So
`logtriage analyze f && echo ok` works in a script.

## What it detects

| Kind | Severity | Source |
|---|---|---|
| `crash` | critical | `FATAL EXCEPTION` + frames + `Caused by` chain |
| `anr` | critical | `ANR in <pkg>`, reason, blocking thread |
| `lmkd` | high | `lowmemorykiller: Kill '<proc>' (pid)` |
| `leak` | high | `OutOfMemoryError`, `GC overhead limit exceeded` |
| `audio` | high/medium | `underrun`, `xrun`, `glitch`, `write blocked for` |
| `thermal` | medium | `Thermal status`, throttling, mitigation |

## Retrace

Reads a standard R8/ProGuard `mapping.txt` and resolves class names, method
names, and line numbers:

```
before   at a.b.c.a(SourceFile:42)
after    at com.grabit.app.ui.Web.load(SourceFile:12)
```

Line rebasing follows the `40:44:... render():10:14` form — obfuscated 42
lands on original 12. When the mapping was built with line-number stripping,
the method name is still recovered but no line number is invented. Frames it
cannot resolve are left alone rather than guessed at.

## Root vs no root

Root is optional and only widens coverage:

- **Rooted:** `logcat -b all` (all buffers incl. crash/events), plus
  `dumpsys media.audio_flinger`, `dumpsys audio`, `dumpsys thermalservice`,
  `/data/anr/traces.txt`, `dmesg`.
- **Unrooted:** plain `logcat -b all -v threadtime -d`. No prompt, no failure.

## Tests

```bash
cd ~/tools/logtriage && python3 test_logtriage.py
```

One file, no framework, ~40 assertions. Covers every detector plus the retrace
math, including two regressions worth naming:

- a crash/ANR block must not swallow the unrelated events after it (`logcat -d`
  emits no blank-line separators, so the block boundary has to be inferred)
- a `FATAL` with no stack must not consume the rest of the log

## Limits

Deliberately scoped out — add when you hit them:

- No live TUI. `watch` is line-buffered stdout; a curses view is the obvious
  next step.
- `capture` is a one-shot snapshot. Ring-buffer rotation for long sessions is
  not implemented.
- Traces are parsed from text. Reading the `logcat` binary buffer format
  (`--binary`, which is what F-Droid's app uses) would be faster on huge logs.
- The retracer covers the mapping.txt subset that matters in practice; it does
  not implement inlining-frame reconstruction, so heavily inlined obfuscated
  stacks may still show fewer frames than the original.