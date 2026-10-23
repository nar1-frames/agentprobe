Debug round 1, 2026-10-21, pg/scan-summary-line @ c8d8778. Verdict: SHIP.
1 Demo output: PASS (3 summary lines before saved lines, exit 0, plain ASCII).
2 Tests: PASS (299 passed; tests diff additions only).
3 Edge cases: PASS (None/{}/empty summary print nothing; zero severities -> "none"; missing keys no exception).
4 --fail-on-error still returns 3: PASS.
5 README example inside bash block as comments, matches real output: PASS.
6 Interactive path untouched: PASS.
Cosmetic: no singular/plural ("1 operational errors"); empty verdicts dict prints "Verdicts: " (malformed input only).
