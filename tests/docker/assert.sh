#!/bin/bash
# Development only: run the checker in a fixture image and compare its exit code and verdict rows
# with an .expect file. Usage: bash tests/docker/assert.sh IMAGE EXPECT_FILE
set -u
image=$1 expect=$2
repo=$(cd "$(dirname "$0")/../.." && pwd)
# After this date every TLS row is INCONCLUSIVE by design, so the live expectations no longer hold.
if [ "$(date -u +%Y%m%d)" -ge 20270503 ]; then
  echo "SKIP: the incident's test certificates have expired; the live end-to-end check is retired"
  exit 0
fi
out=$(docker run --rm -v "$repo:/w:ro" "$image" bash /w/emudhra-cli-trust-check.sh --scan /opt 2>&1); rc=$?
printf '%s\n' "$out"
echo "----- expectations ($expect)"
fail=0
while read -r kind rest; do
  case "$kind" in
    ""|"#"*) continue ;;
    exit) if [ "$rc" = "$rest" ]; then echo "ok    exit $rc"; else echo "FAIL  exit $rc, expected $rest"; fail=1; fi ;;
    none) if printf '%s\n' "$out" | grep -qE "^  $rest +"; then echo "FAIL  unexpected $rest rows"; fail=1; else echo "ok    no $rest rows"; fi ;;
    *) if printf '%s\n' "$out" | grep -E "^  $kind +" | grep -qF -- "$rest"; then echo "ok    $kind $rest"
       else echo "FAIL  no $kind row for: $rest"; fail=1; fi ;;
  esac
done < "$expect"
if [ "$fail" -ne 0 ] && printf '%s\n' "$out" | grep -q 'control site unreachable'; then
  echo "note: a control site was unreachable, so the failure may be the network rather than the script"
fi
exit "$fail"
