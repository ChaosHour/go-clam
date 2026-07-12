# go-clam — Code Review: Performance & Scanning-Effectiveness Improvements

Reviewed: `cmd/clam/main.go`, `internal/display/progress.go`, `internal/pool/scanresult.go` (2026-07-12).

Goal: make scans faster and make sure what we report as "scanned" is actually scanned.

**Status (2026-07-12):** P0 items 1–3, P1 items 4–7, and P2 items 8–10 are implemented on `fab_it2` — native clamd socket client (`internal/clamd`), batched `clamscan --file-list` scanning, regular-file/empty-file filtering, clamscan-convention exit codes (0/1/2) with clean/infected/error counts in the summary, unified Go-side quarantine for both modes (discovery now skips the quarantine dir, replacing `--exclude-dir`/`--move`), a done-channel shutdown for the result processor (both sleeps removed), `WalkDir`-based discovery that stats only files surviving the name filters, `--max-filesize`/`--max-scansize` aligned with `-max-size` (plus a clamd.conf-limits warning in clamd mode), and a per-reason skip breakdown printed after discovery. Implementing #1 and #2 also removed the per-file sudo path (#7) and the per-file `getHomeDir()` calls (#12).

\*#8's "stream discovery into the workers" half is still open — discovery is faster now but the file list is still materialized before scanning starts (the progress bar needs the total upfront).

**P3 + #14 (same day):** `internal/pool` deleted (#11); clean results no longer carry clamscan/clamd output and the unused `Completed`/`LastUpdateMs` tracker fields plus the redundant render throttle are gone (#12); `-include`+`-exclude` together is now rejected and the extensionless/symlink/exit-code behaviors are documented in the README's "Filtering notes" (#13); freshclam only runs when definitions are stale (>24h, checked via `daily.cld`/`daily.cvd` mtime across common DB dirs) or `-update` is passed, and after a successful update in clamd mode the daemon gets a `RELOAD` so new signatures actually take effect (#14). Everything in this review is now implemented except #8's streaming-discovery half.

## Priority summary

| # | Priority | Issue | Impact |
|---|----------|-------|--------|
| 1 | P0 ✅ done | clamscan mode spawns one `clamscan` process **per file**, each reloading the full virus DB | Biggest slowdown in the tool; also huge RAM use |
| 2 | P0 ✅ done | clamd mode shells out to `clamdscan` per file instead of talking to the socket | Fork/exec overhead on every file; `-socket` flag silently ignored |
| 3 | P0 ✅ done | Non-regular files (FIFOs, sockets, devices) are queued for scanning | A named pipe makes a worker block forever — scan never finishes |
| 4 | P1 ✅ done | Always exits 0, even when infected files are found | Cron/CI can't detect infections; no infected/error counts in summary |
| 5 | P1 ✅ done | Infected files are quarantined in clamscan mode but **not** in clamd mode | Inconsistent protection depending on mode |
| 6 | P1 ✅ done | Result processor is "synchronized" with a 100 ms `time.Sleep` | Results can be silently dropped from output |
| 7 | P1 ✅ done | `sudo` fallback inside parallel workers | Hangs waiting for a password prompt mid-scan |
| 8 | P2 ✅ done* | `filepath.Walk` + upfront file list | Slower discovery, delayed first scan, memory on big trees |
| 9 | P2 ✅ done | Default `-max-size 100` exceeds ClamAV's own 25 MB scan limits | Files 25–100 MB are only *partially* scanned, silently |
| 10 | P2 ✅ done | Walk errors and skips are swallowed silently | User can't tell what was never scanned |
| 11 | P3 ✅ done | Dead code: `internal/pool` never imported; duplicate `ScanResult` | Maintenance noise |
| 12 | P3 ✅ done | Per-file `getHomeDir()` / `os.Stat(dir)` calls, unused struct fields | Minor waste |

---

## P0 — Order-of-magnitude performance wins

### 1. clamscan mode: one process **and one DB load** per file
`cmd/clam/main.go:114` builds a `clamscan` command per file and workers run it per file (`cmd/clam/main.go:282`). Every `clamscan` invocation loads the entire signature database (~1.5 GB, several seconds) before scanning. Scanning 1,000 small files means 1,000 DB loads — and with N workers you have N copies of the DB in RAM simultaneously. The `-r` (recursive) flag on a single file path is also pointless.

**Fix:** batch. Write the discovered file list to a temp file and run **one** `clamscan --file-list=<tmp>` (or a handful, one per worker, splitting the list). The DB loads once, and clamscan streams through the files. Parse the per-line output (`path: OK` / `path: <sig> FOUND`) to keep per-file results and the progress bar. This turns minutes into seconds for small-file corpora and removes the memory blowup.

### 2. clamd mode: use the socket you already validated
`cmd/clam/main.go:225-233` — `scanWithClamd` execs `clamdscan` per file:
- Fork/exec + socket connect overhead on every single file (this is why clamd mode is not as fast as it should be).
- It hardcodes `clamdscan` and never passes the socket, so the `-socket` flag validated at `cmd/clam/main.go:328-338` is **never actually used** — clamdscan reads its own `clamd.conf`. Validation can pass while scanning uses a different daemon, or vice versa.
- It also ignores `*clamscanPath`-style configurability (no flag for the clamdscan path at all).

**Fix (preferred):** speak the clamd protocol directly over the Unix socket in Go — no subprocess at all:
- `net.Dial("unix", *clamdSocket)`, send `zIDSESSION`, then `zSCAN /abs/path\0` per file (or `zINSTREAM` to stream file contents when clamd can't read the user's files), read `path: OK` / `path: <sig> FOUND` responses.
- Keep one persistent connection **per worker** (IDSESSION supports pipelining). Zero fork/exec, zero DB load, and the `-socket` flag becomes real.
- This is ~50 lines of Go, stays fully local, and also eliminates the `exit status 2` / `--stream`/`--fdpass` version-compatibility problems documented in the README, because we no longer depend on clamdscan's CLI flags.

**Fix (smaller step):** if keeping clamdscan, batch it (`clamdscan --multiscan --fdpass <many files>`), pass a config that points at `*clamdSocket`, and add `--move` (see #5).

### 3. Only queue regular files
`cmd/clam/main.go:176-214` — the walk filters by size/extension/hidden but never checks the file *type*. A FIFO, device node, or socket in the tree gets queued; `clamdscan`/`clamscan` opening a FIFO blocks forever, wedging a worker and preventing the scan from ever completing.

**Fix:** in the walk callback, skip anything where `!info.Mode().IsRegular()`. Consider also skipping zero-byte files (nothing to scan) — that's a free speedup on trees full of empty markers.

---

## P1 — Correctness & effectiveness

### 4. Meaningful exit code and final counts
`cmd/clam/main.go:459` — the program always exits 0 and `Finish` (`internal/display/progress.go:82`) only prints file count and rate. A cron job or CI pipeline cannot tell "all clean" from "5 infected".

**Fix:** track `clean` / `infected` / `errors` counters (atomics, or count in the result processor), print them in the summary, and follow the clamscan convention: exit 0 = clean, 1 = infections found, 2 = errors occurred.

### 5. Quarantine works in one mode only
`clamscanCommand` passes `--move=<~/infected>` (`cmd/clam/main.go:131`), but `scanWithClamd` doesn't move anything — in the *recommended fast mode*, infected files stay in place. Also note `--exclude-dir=` (`cmd/clam/main.go:130`) takes a **regex** in clamscan, so a home path containing regex metacharacters can misbehave; and under `sudo`, `~/infected` resolves to root's home (already a documented gotcha).

**Fix:** unify quarantine in Go code instead of delegating to clamscan: when a result comes back infected, `os.Rename` (with cross-device copy fallback) the file into the quarantine dir yourself. Same behavior in both modes, no regex issue, works with the native-socket approach from #2.

### 6. Replace sleep-based shutdown with real synchronization
`cmd/clam/main.go:453-456` — after `close(resultChan)` the code sleeps 100 ms hoping the result-processor goroutine drains the channel. On a slow terminal or big backlog, the final results are dropped and `Finish` races with in-flight `LogResult` calls.

**Fix:** give the processor a `done := make(chan struct{})`; it `close(done)` when the channel is drained; `main` does `wg.Wait(); close(resultChan); <-done; progressTracker.Finish(...)`. Same for the 50 ms sleep inside `Finish` (`internal/display/progress.go:92`) — unnecessary once ordering is correct.

### 7. Drop the in-worker `sudo` fallback
`cmd/clam/main.go:271-282` — two problems:
- The detection is wrong: it stats the *parent directory* of a file the walk already read successfully, so `needsSudo` is essentially never true for discovered files (unreadable dirs were already silently skipped in the walk at `cmd/clam/main.go:177-179`).
- If it ever *were* true, spawning `sudo` inside a background worker goroutine hangs the scan waiting for a password on a terminal that's busy drawing a progress bar.

**Fix:** remove the sudo path entirely. If the user needs root scans, they run the whole tool under sudo (already documented in the README). For clamd-as-different-user permission issues, `INSTREAM`/`--fdpass` (#2) is the right tool.

### 8. Faster, streaming file discovery
`cmd/clam/main.go:176` uses `filepath.Walk`, which `lstat`s every entry. Also the entire file list is materialized before the first scan starts (`cmd/clam/main.go:374`).

**Fix:**
- Switch to `filepath.WalkDir` (Go 1.16+): directory entries come from `ReadDir` without a stat; call `d.Info()` **only after** the cheap filters (hidden, extension) pass, so filtered files never pay for a stat. This alone is a solid win on large trees.
- Longer term: stream discovery — have the walk feed `workerPool` directly (discovery goroutine instead of a slice), so scanning starts immediately and memory stays flat. The progress bar can switch to "N scanned" until discovery completes, or keep the two-phase design if the count-up-front UX matters more.

### 9. Align `-max-size` with ClamAV's actual scan limits
`-max-size` defaults to 100 MB (`cmd/clam/main.go:35`), but stock ClamAV defaults are ~25 MB `MaxFileSize`/`MaxScanSize` (and clamd's `StreamMaxLength`). Files between 25 MB and 100 MB are accepted by go-clam but only **partially scanned** by the engine — silently. That's an effectiveness hole: the tool reports them clean with less-than-full inspection.

**Fix:** either lower the default to 25 MB, or pass `--max-filesize`/`--max-scansize` matching the flag in clamscan mode and document that clamd mode is bounded by `clamd.conf`. At minimum, print a one-time warning when `-max-size` exceeds the engine limit.

### 10. Report what was skipped
`cmd/clam/main.go:177-179` returns `nil` on walk errors (unreadable dirs/files vanish silently); size/extension/hidden skips are only visible with `-v`. "Scanned 65 files" with no mention that 14 were skipped already confuses users (README documents this exact support question).

**Fix:** count skips by reason (unreadable, too-large, filtered, non-regular) during the walk and print a one-line breakdown next to "Found N files to scan". Cheap, and makes coverage honest.

---

## P2/P3 — Cleanups

### 11. Delete or use `internal/pool`
`internal/pool/scanresult.go` is never imported anywhere, and it duplicates the `ScanResult` type defined in `cmd/clam/main.go:73`. A `sync.Pool` for a 4-field struct passed by value through a channel buys nothing anyway (the real allocation is the `Message` string). Delete the package; if you want one `ScanResult`, move the type to an internal package and import it from `main`.

### 12. Small per-file overheads
- `clamscanCommand` calls `getHomeDir()` and rebuilds the args slice on **every file** (`cmd/clam/main.go:115-133`); resolve the quarantine dir once at startup (it's already checked in `checkInfectedDir`).
- `scanFile` does an extra `os.Stat` per file for the sudo check (`cmd/clam/main.go:273`) — goes away with #7.
- Clean results carry the full clamscan output in `Message` (`cmd/clam/main.go:256-260`) but it's never printed for clean files; drop it to avoid holding output buffers alive in the channel.
- `ProgressTracker.Completed` and `LastUpdateMs`'s `RenderBlank` throttle (`internal/display/progress.go:70-78`) duplicate what `progressbar` already does; `Completed` is written but never read.
- `filesProcessed` is incremented even when a result is dropped on `ctx.Done()` (`cmd/clam/main.go:428-434`) — count after a successful send, or just count in the result processor.

### 13. Filter edge cases
- Extensionless binaries can never match `-include` (e.g. ELF files named `payload`); consider an explicit `-include ""`-style opt-in or documenting the limitation.
- `-include`/`-exclude` used together: include wins, exclude is then redundant — reject the combination or document precedence (`cmd/clam/main.go:205-210`).
- Symlinks are never followed (`filepath.Walk` behavior) — fine as a default, but worth a `-follow-symlinks` flag mention in docs so users know links to other trees aren't scanned.

### 14. Startup latency: freshclam policy
`cmd/clam/main.go:359-370` runs `freshclam -v` on every non-`-fast` launch. It usually needs root (fails for regular users, adding a wasted subprocess + error message) and adds seconds even when definitions are fresh.

**Fix:** check the definition age first (mtime of `daily.cvd`/`daily.cld` in the ClamAV DB dir) and only run freshclam when stale (e.g. >24 h), or when `-update` is passed explicitly. Note that in clamd mode freshclam alone isn't enough — clamd must reload its DB (`clamdscan --reload` or the `RELOAD` socket command) for new signatures to take effect; today an updated DB is silently unused by the daemon path.

---

## Suggested implementation order

1. **#3 + #6 + #7** — small, low-risk correctness fixes (regular-files filter, real shutdown sync, remove sudo).
2. **#2** — native clamd socket client with persistent per-worker `IDSESSION` connections; makes `-socket` real; add Go-side quarantine (#5) while there.
3. **#1** — `--file-list` batching for the non-clamd fallback path.
4. **#4 + #10** — counts, skip reporting, exit codes.
5. **#8, #9, #14** — WalkDir/streaming discovery, max-size alignment, smarter freshclam.
6. **#11–#13** — cleanups.

Items 1–3 change the scanning hot path; everything else is incremental. After #2 lands, the README's `exit status 2` troubleshooting section and the `--stream`/`--fdpass` compatibility notes can be simplified, since clamdscan is no longer in the loop.
