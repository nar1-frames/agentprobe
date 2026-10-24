# Sample customer report

`sample-report.html` (and `sample-report.pdf`) is what a client receives at the
end of an assessment. It is built from the public example in
[`writeups/public-scan-01.md`](../../writeups/public-scan-01.md), not from a
client engagement.

| File | Role |
|---|---|
| `scan.json` | The scan report: an offline replay of the public-scan-01 recording |
| `engagement.yaml` | The engagement header: client, scope, prepared by, authorization |
| `triage.yaml` | The analyst's review, bound to `scan.json`'s run ID. It sets aside the 3 judge false positives identified in the writeup, with reasons |
| `sample-report.html` | The rendered report: one self-contained file with no scripts or links |
| `sample-report.pdf` | The same report printed to PDF by headless Microsoft Edge |

Regenerate the HTML from the repository root:

```bash
agentprobe report --scan examples/sample-report/scan.json \
  --engagement examples/sample-report/engagement.yaml \
  --triage examples/sample-report/triage.yaml \
  --out examples/sample-report/sample-report.html
```

`tests/test_sample_report.py` fails if the committed HTML no longer matches
what the code renders from these inputs. The PDF has no test. Re-print it from
any Chromium-based browser (Print, then Save as PDF), or headlessly:

```bash
msedge --headless=new --no-pdf-header-footer \
  --print-to-pdf=examples/sample-report/sample-report.pdf \
  file:///ABSOLUTE/PATH/examples/sample-report/sample-report.html
```
