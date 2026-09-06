"""Render analysis JSON as deterministic publication tables."""

import argparse
import json


def _num(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def _ci(value):
    if not value or len(value) != 2:
        return "n/a"
    return f"[{_num(value[0])}, {_num(value[1])}]"


def render_markdown(results):
    """Return stable Markdown tables without recomputing any statistics."""

    lines = [
        "# AgentProbe analysis tables",
        "",
        "Generated from an `research.analyze` JSON artifact. Values are not recomputed here.",
        "",
    ]
    metadata = results.get("metadata") or {}
    if metadata:
        lines += [
            f"Corpus: {metadata.get('corpus_responses', 'n/a')} responses; "
            f"SHA-256 `{metadata.get('corpus_sha256', 'n/a')}`.",
            "",
        ]
    lines += [
        "## RQ1 — Judge validity against human labels",
        "",
        "| Judge | Temp | n | Accuracy | Accuracy 95% CI | Cohen's κ | κ 95% CI |",
        "|---|---:|---:|---:|---|---:|---|",
    ]
    for row in results.get("rq1", []):
        lines.append(
            f"| `{row['judge_model']}` | {_num(row['temperature'])} | {row['n']} | "
            f"{_num(row['accuracy'])} | {_ci(row.get('accuracy_ci_95'))} | "
            f"{_num(row['cohens_kappa'])} | {_ci(row.get('cohens_kappa_ci_95'))} |"
        )

    lines += [
        "",
        "### RQ1 category breakdown",
        "",
        "| Judge | Temp | Category | n | Accuracy | Cohen's κ |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for row in results.get("rq1", []):
        for category, values in sorted((row.get("by_category") or {}).items()):
            lines.append(
                f"| `{row['judge_model']}` | {_num(row['temperature'])} | `{category}` | "
                f"{values['n']} | {_num(values['accuracy'])} | {_num(values['cohens_kappa'])} |"
            )

    lines += [
        "",
        "## RQ2 — Judge reliability across repeated runs",
        "",
        "| Judge | Temp | Complete items | Expected k | Self-agreement | SA 95% CI | Fleiss' κ | κ 95% CI | Missing groups | Errors |",
        "|---|---:|---:|---:|---:|---|---:|---|---:|---:|",
    ]
    for row in results.get("rq2", []):
        lines.append(
            f"| `{row['judge_model']}` | {_num(row['temperature'])} | {row['items']} | "
            f"{row['expected_k']} | {_num(row['self_agreement'])} | "
            f"{_ci(row.get('self_agreement_ci_95'))} | {_num(row['fleiss_kappa'])} | "
            f"{_ci(row.get('fleiss_kappa_ci_95'))} | {row.get('missing_item_groups', 0)} | "
            f"{row.get('judge_errors_excluded', 0)} |"
        )

    rq3 = results.get("rq3") or {}
    lines += [
        "",
        "## RQ3 — Keyword stage versus judge",
        "",
        f"Reference judge: `{rq3.get('reference_judge', 'n/a')}` @ {_num(rq3.get('temperature'))}",
        "",
        f"Raw agreement: **{_num(rq3.get('raw_agreement'))}**; "
        f"keyword-decisive rate: **{_num(rq3.get('keyword_decisive_rate'))}**.",
        f"Disagreements recorded for qualitative review: **{len(rq3.get('disagreements', []))}**.",
        "",
        "## RQ4 — Proxy error overlap",
        "",
    ]
    rq4 = results.get("rq4_proxy_error_overlap")
    if rq4:
        lines += [
            f"Weak judge: `{rq4.get('weak_judge', 'n/a')}` @ {_num(rq4.get('temperature'))}; "
            f"n={rq4.get('n', 0)}.",
            "",
            f"Keyword proxy errors: {rq4.get('keyword_proxy_errors', 0)}; "
            f"weak-judge errors: {rq4.get('weak_judge_errors', 0)}; "
            f"joint errors: {rq4.get('joint_errors', 0)}; "
            f"error-union overlap: {_num(rq4.get('error_overlap_rate'))} "
            f"({_ci(rq4.get('error_overlap_rate_ci_95'))} 95% CI).",
            f"Keyword/judge disagreement: {_num(rq4.get('keyword_judge_disagreement'))} "
            f"({_ci(rq4.get('keyword_judge_disagreement_ci_95'))} 95% CI).",
            "",
            f"> Interpretation: {rq4.get('interpretation', 'not specified')}",
        ]
    else:
        lines.append("No RQ4 result is present in this artifact.")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Export analysis JSON to Markdown tables.")
    ap.add_argument("--results", default="data/results.json")
    ap.add_argument("--out", default="docs/generated_results.md")
    args = ap.parse_args()
    with open(args.results, encoding="utf-8") as f:
        results = json.load(f)
    text = render_markdown(results)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"Wrote publication tables to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
