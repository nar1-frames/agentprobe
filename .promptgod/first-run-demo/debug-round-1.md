Debug round 1, 2026-10-21, branch pg/first-run-demo @ 73429b0. Verdict: SHIP.
1 Fresh clone offline run: PASS (exit 0, keys unset, sockets patched to raise).
2 Timing: PASS (0.29 s).
3 Report content: PASS (14 results: 10 SAFE, 3 VULNERABLE, 1 PARTIAL; Mitigation Map present; HTML well-formed).
4 Sanitization: PASS (0 hits in recording; only CSS/word hits in HTML; public OWASP/GitHub links).
5 Tests: PASS (297 passed; no existing test touched).
6 Public hygiene: PASS (exact-path exception; secret scan still applies; other replay files rejected).
Extras: no files outside reports/; README steps 1-4 in order; judge gate refuses smaller judge (exit 2); equal-size judge allowed by design.
Pre-existing observations: equal-size judge with no recording => 14 op errors but exit 0 without --fail-on-error; non-interactive CLI prints no verdict summary; deep-path venv install fails on Windows without long paths.
