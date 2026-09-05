#!/usr/bin/env bash
# Ledger hardware evidence pack.
#
# Drives the hardware suite through the device states that unit tests cannot
# reach, and writes a timestamped markdown transcript suitable for attaching to
# a PR as review evidence.
#
# This is deliberately interactive. Every phase that needs the device in a
# particular state stops and tells the operator what to do, because the whole
# point is to exercise states a machine cannot put the device into.
#
#   ./scripts/ledger-hardware-runbook.sh --model "Nano Gen5" \
#       --firmware 1.3.0 --app-version 1.9.2
#
# Run it once per device in the target matrix:
#   Nano Gen5, plus one of Nano S Plus / Nano X, on macOS and on Linux.
#
# Exit status is 0 if every phase produced its expected outcome. A phase whose
# expectation is "this must fail" passes when it fails.

set -uo pipefail

MODEL=""
FIRMWARE=""
APP_VERSION=""
OUT_DIR="ledger-evidence"
SKIP_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) MODEL="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --firmware) FIRMWARE="${2:-}"; shift 2 ;;
    --app-version) APP_VERSION="${2:-}"; shift 2 ;;
    --non-interactive) SKIP_INTERACTIVE=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$MODEL" ]]; then
  echo "error: --model is required, e.g. --model 'Nano Gen5'" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"
mkdir -p "$OUT_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SLUG="$(echo "$MODEL" | tr '[:upper:] ' '[:lower:]-')"
REPORT="$OUT_DIR/ledger-evidence-${SLUG}-$(uname -s | tr '[:upper:]' '[:lower:]')-${STAMP}.md"

PASS=0
FAIL=0
CRASH=0
SKIP=0
declare -a SUMMARY

log()  { printf '%s\n' "$*" >>"$REPORT"; }
say()  { printf '\033[1m%s\033[0m\n' "$*" >&2; }

prompt() {
  # $1 = what the operator must do
  if [[ "$SKIP_INTERACTIVE" == "1" ]]; then
    say "[non-interactive] skipping operator step: $1"
    return 1
  fi
  say ""
  say "ACTION REQUIRED: $1"
  read -r -p "  press Enter when done, or 's' to skip this phase: " reply </dev/tty
  [[ "$reply" == "s" ]] && return 1
  return 0
}

# phase <name> <expectation: pass|fail> <command...>
phase() {
  local name="$1"; shift
  local expect="$1"; shift
  say "── $name"
  log ""
  log "## $name"
  log ""
  log "Expectation: the command below must **$expect**."
  log ""
  log '```'
  local start rc
  start=$(date +%s)
  # Tee so the operator sees progress and the report keeps the transcript.
  "$@" >>"$REPORT" 2>&1
  rc=$?
  local elapsed=$(( $(date +%s) - start ))
  log '```'
  log ""
  log "Exit status: \`$rc\` after ${elapsed}s."

  # Three outcomes, not two. A signal-terminated process is never "as
  # expected", even for a phase that expects failure: `rc > 128` means SIGTRAP,
  # an abort or a kill, and the reconnect phase exists precisely to detect that
  # crash. Folding it into "nonzero, therefore the expected failure" let the
  # runbook mark the very regression it was written to catch as a pass.
  if [[ $rc -gt 128 ]]; then
    local sig=$((rc - 128))
    CRASH=$((CRASH+1)); SUMMARY+=("CRASH $name (signal $sig)")
    log "Result: **CRASHED** — terminated by signal $sig. This is a regression,"
    log "not an expected failure, however the phase's expectation was written."
    say "   CRASHED (signal $sig after ${elapsed}s)"
    return
  fi

  local ok=0
  [[ "$expect" == "pass" && $rc -eq 0 ]] && ok=1
  [[ "$expect" == "fail" && $rc -ne 0 ]] && ok=1

  if [[ $ok == 1 ]]; then
    PASS=$((PASS+1)); SUMMARY+=("PASS  $name"); log "Result: **as expected**."
    say "   ok (${elapsed}s)"
  else
    FAIL=$((FAIL+1)); SUMMARY+=("FAIL  $name"); log "Result: **NOT as expected**."
    say "   UNEXPECTED (exit $rc after ${elapsed}s)"
  fi
}

# Run one #[ignore]d hardware test by name.
# Run one #[ignore]d hardware test by name, through the repository recipe so it
# gets the same feature set and flags as every other entry point. Raw `cargo`
# here would drift from the Justfile the moment the feature matrix changes,
# which is exactly what CLAUDE.md forbids.
hw_test() {
  just rust-ledger-hw-test "$1"
}

skipped() {
  SKIP=$((SKIP+1))
  SUMMARY+=("SKIP  $1")
  log ""; log "## $1"; log ""; log "_Skipped by the operator._"
  say "   skipped"
}

# ── header ────────────────────────────────────────────────────────────────
cat >"$REPORT" <<EOF
# Ledger hardware evidence: $MODEL

| | |
|---|---|
| Device | $MODEL |
| Host | \`$(uname -srm)\` |
| Date (UTC) | $STAMP |
| Repo | \`$(git rev-parse --show-toplevel 2>/dev/null || echo "$REPO_ROOT")\` |
| Commit | \`$(git rev-parse HEAD 2>/dev/null || echo unknown)\` |
| Branch | \`$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)\` |
| Dirty | \`$(test -n "$(git status --porcelain 2>/dev/null)" && echo yes || echo no)\` |
| solana-remote-wallet | \`$(grep -A2 'name = "solana-remote-wallet"' rust/Cargo.lock 2>/dev/null | grep version | head -1 | sed 's/.*"\(.*\)".*/\1/' || echo unknown)\` |
| Device firmware | \`${FIRMWARE:-not recorded}\` |
| Solana app version | \`${APP_VERSION:-not recorded}\` |

Generated by \`scripts/ledger-hardware-runbook.sh\`. Each phase records the
command, its full output, and whether the outcome matched what that device state
should produce. A phase expecting failure passes when it fails.
EOF

# ── phase 1: unlocked, Solana app open ────────────────────────────────────
if prompt "Unlock the $MODEL and open the Solana app. Quit Ledger Live."; then
  phase "1. Unlocked, Solana app open" pass just rust-test-ledger
else
  skipped "1. Unlocked, Solana app open"
fi

# ── phase 2: locked ───────────────────────────────────────────────────────
log ""
log "> The suite must **fail** here rather than skip. Skipping on a locked"
log "> device is how a locked Gen5 once made this whole suite look green while"
log "> testing nothing: \`try_connect\` only skips when no device is attached."
if prompt "Lock the $MODEL (leave it plugged in). Do not unlock it."; then
  phase "2. Locked device must fail, not skip" fail just rust-test-ledger
else
  skipped "2. Locked device must fail, not skip"
fi

# ── phase 3: Ledger Live holding the device ───────────────────────────────
log ""
log "> Ledger Live keeps the HID handle for as long as it runs. The error must"
log "> name that, not just the cable."
if prompt "Unlock the device, open the Solana app, then START Ledger Live."; then
  phase "3. Ledger Live holds the handle" fail just rust-test-ledger
else
  skipped "3. Ledger Live holds the handle"
fi

# ── phase 4: app closed, exercising auto-launch ───────────────────────────
log ""
log "> With \`auto_open_app\` at its default, connect should launch the Solana"
log "> app from the BOLOS dashboard and retry across the USB re-enumeration."
log "> Approve the launch on the device if it asks."
if prompt "Quit Ledger Live. Unlock the device and leave it on the DASHBOARD (Solana app closed)."; then
  phase "4a. Auto-launch from the dashboard" pass just rust-ledger-open-app
  phase "4b. Suite after auto-launch" pass just rust-test-ledger
else
  skipped "4. Auto-launch from the dashboard"
fi

# ── phase 5: unplug/replug mid-suite ──────────────────────────────────────
log ""
log "> The process-wide device thread must survive this. Before the singleton"
log "> fix, any connect/drop/reconnect cycle aborted the process with SIGTRAP"
log "> inside CoreFoundation on macOS. A crash here, rather than a clean error,"
log "> is a regression of that fix."
if prompt "Unlock, open the Solana app. During the NEXT run, unplug the device and plug it back in."; then
  phase "5. Unplug/replug mid-suite must not crash the process" fail just rust-test-ledger
  log ""
  log "Read the transcript above: a non-zero exit with a \`NotAvailable\` error is"
  log "the expected outcome. A SIGTRAP, abort, or signal-terminated process is a"
  log "regression even though it also exits non-zero."
else
  skipped "5. Unplug/replug mid-suite must not crash the process"
fi

# ── phase 6: reconnect regression, 20 iterations ──────────────────────────
log ""
log "> The reconnect cycle is the exact shape that used to abort the test binary."
log "> Twenty consecutive clean runs in one process is the evidence that the"
log "> singleton device thread holds."
if prompt "Unlock the device and open the Solana app. This runs 20 times and needs no button presses."; then
  say "── 6. Reconnect regression x20"
  log ""; log "## 6. Reconnect regression, 20 iterations"; log ""
  log "Expectation: 20 of 20 must **pass**."; log ""; log '```'
  reconnect_fail=0
  reconnect_crash=0
  for i in $(seq 1 20); do
    printf 'iteration %02d: ' "$i" >>"$REPORT"
    just rust-ledger-hw-reconnect >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
      echo "ok" >>"$REPORT"
    elif [[ $rc -gt 128 ]]; then
      echo "CRASHED (signal $((rc - 128)))" >>"$REPORT"
      reconnect_crash=$((reconnect_crash+1))
    else
      echo "FAILED (exit $rc)" >>"$REPORT"; reconnect_fail=$((reconnect_fail+1))
    fi
    printf '.' >&2
  done
  printf '\n' >&2
  log '```'; log ""
  log "Failures: **$reconnect_fail of 20**. Signal-terminated: **$reconnect_crash**."
  if [[ $reconnect_crash -gt 0 ]]; then
    CRASH=$((CRASH+1))
    SUMMARY+=("CRASH 6. Reconnect regression x20 ($reconnect_crash crashed)")
    say "   CRASHED: $reconnect_crash of 20 killed by a signal"
  elif [[ $reconnect_fail -eq 0 ]]; then
    PASS=$((PASS+1)); SUMMARY+=("PASS  6. Reconnect regression x20"); say "   ok, 20/20"
  else
    FAIL=$((FAIL+1)); SUMMARY+=("FAIL  6. Reconnect regression x20 ($reconnect_fail failed)")
    say "   UNEXPECTED: $reconnect_fail of 20 failed"
  fi
else
  skipped "6. Reconnect regression, 20 iterations"
fi

# ── phase 7: rejection must not kill the session (F-14) ───────────────────
log ""
log "> The defect: \`with_session\` dropped the session on any error, including"
log "> \`UserRejected\`, and only \`connect\` could build one. So declining a single"
log "> transaction made every later signature fail with \"no Ledger session\"."
if prompt "Unlock, open the Solana app. You will be asked to REJECT one prompt, then APPROVE the next."; then
  phase "7. Reject, then sign again on the same signer" pass \
    hw_test test_ledger_rejection_does_not_kill_the_session
else
  skipped "7. Reject, then sign again on the same signer"
fi

# ── phase 8: unplug/replug recovery on the same signer (F-14) ─────────────
log ""
log "> A transport error correctly drops the session. Before the re-establish"
log "> logic, nothing could rebuild it, so the signer stayed dead after a replug"
log "> even though the device was back. No new signer is constructed here."
if prompt "You will APPROVE one signature, then UNPLUG and REPLUG the device within 45s, then APPROVE another."; then
  phase "8. Same signer recovers from unplug/replug" pass \
    hw_test test_ledger_signer_survives_unplug_replug
else
  skipped "8. Same signer recovers from unplug/replug"
fi

# ── phase 9: probes must not hang behind a prompt (F-1) ───────────────────
log ""
log "> One process serializes to one on-device confirmation. A probe arriving"
log "> while the device is mid-prompt must return within its own 10s tier"
log "> deadline reporting unavailable, not block until the prompt is answered."
if prompt "A signature will start. LEAVE THE PROMPT UNANSWERED until told otherwise."; then
  phase "9. Probes return while a signature is pending" pass \
    hw_test test_ledger_probe_returns_while_a_signature_is_pending
else
  skipped "9. Probes return while a signature is pending"
fi

# ── phase 10: two devices ─────────────────────────────────────────────────
log ""
log "> Device selection must be explicit. With two attached and no host path,"
log "> connect must error and list both. With a path, it must use that device"
log "> and only that one -- including the dashboard auto-launch, which used to"
log "> fall back to an arbitrary device on an exact-path miss."
if prompt "Attach a SECOND Ledger. Both unlocked, Solana app open on both."; then
  phase "10a. No host path errors listing both devices" fail just rust-test-ledger
  log ""
  log "Read the transcript: the error must name **both** device paths. Then run"
  log "\`just rust-ledger-open-app\` by hand against each explicit path and confirm"
  log "only the named device reacts. Record the outcome here:"
  log ""
  log "- [ ] error listed both paths"
  log "- [ ] explicit path A connected to device A"
  log "- [ ] explicit path B connected to device B"
  log "- [ ] auto-launch affected only the named device"
else
  skipped "10. Two devices attached"
fi

# ── phase 11: blind signing for non-ASCII off-chain messages ──────────────
log ""
log "> A payload that is not printable ASCII goes as format 1 (LimitedUtf8),"
log "> which the Solana app refuses unless blind signing is enabled."
if prompt "Leave ONE device attached, unlocked, Solana app open, blind signing DISABLED."; then
  phase "11a. Non-ASCII off-chain message, blind signing disabled" pass \
    hw_test test_ledger_non_ascii_offchain_message_needs_blind_signing
  log ""
  log "The test reports which branch it took; confirm it says \"refused\" here."
  if prompt "Now ENABLE blind signing in the Solana app settings."; then
    phase "11b. Non-ASCII off-chain message, blind signing enabled" pass \
      hw_test test_ledger_non_ascii_offchain_message_needs_blind_signing
    log ""
    log "Confirm it says \"signed\" here. Remember to disable blind signing again."
  else
    skipped "11b. Non-ASCII off-chain message, blind signing enabled"
  fi
else
  skipped "11. Blind signing for non-ASCII off-chain messages"
fi

# ── summary ───────────────────────────────────────────────────────────────
{
  echo ""
  echo "## Summary"
  echo ""
  echo '```'
  printf '%s\n' "${SUMMARY[@]}"
  echo '```'
  echo ""
  echo "**$PASS as expected, $FAIL not as expected, $CRASH crashed, $SKIP skipped.**"
  echo ""
  if [[ $CRASH -gt 0 ]]; then
    echo "> A phase was terminated by a signal. That is a regression of the"
    echo "> process-wide device thread, not an expected failure, and this report"
    echo "> should not be attached as evidence until it is understood."
  fi
  if [[ $SKIP -gt 0 ]]; then
    echo "> $SKIP phase(s) were skipped. Skipped is not passed: the matrix is"
    echo "> incomplete and the gaps are listed above."
  fi
  echo ""
  echo "### Matrix coverage"
  echo ""
  echo "This run covers **$MODEL on $(uname -s)**. The target matrix is Nano Gen5"
  echo "plus one of Nano S Plus / Nano X, each on macOS and Linux. Attach one"
  echo "report per cell."
} >>"$REPORT"

say ""
say "Report: $REPORT"
printf '%s\n' "${SUMMARY[@]}" >&2
say "$PASS as expected, $FAIL not as expected, $CRASH crashed, $SKIP skipped."
# Nonzero on any unexpected outcome or any crash. Skips do not fail the run,
# because skipping is a legitimate operator choice, but they are reported.
[[ $FAIL -eq 0 && $CRASH -eq 0 ]]
