"""Model metadata and scan-level strength invariants."""

import re


def parse_model_size_b(text):
    """Extract a parameter count in billions from a model identifier."""

    if not text:
        return None
    match = re.search(r"(\d+(?:\.\d+)?)\s*[bB]\b", str(text))
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)b", str(text).lower())
    return float(match.group(1)) if match else None


def validate_judge_strength(target_model, judge_model, target_metadata=None,
                            judge_metadata=None):
    """Fail closed unless the configured judge is at least as strong as target.

    Parameter size is preferred. For providers that do not publish it, both
    config blocks may provide an explicit comparable integer ``strength_rank``
    (for example, an organization-maintained model capability tier).
    """

    target_metadata = target_metadata or {}
    judge_metadata = judge_metadata or {}
    target_size = parse_model_size_b(target_model)
    judge_size = parse_model_size_b(judge_model)
    target_rank = target_metadata.get("strength_rank")
    judge_rank = judge_metadata.get("strength_rank")
    if target_size is None and target_rank is not None:
        target_size = float(target_rank)
    if judge_size is None and judge_rank is not None:
        judge_size = float(judge_rank)
    if target_size is None or judge_size is None:
        raise ValueError(
            "Cannot verify judge strength from configured model names "
            f"(target={target_model!r}, judge={judge_model!r}); "
            "provide parameter sizes or comparable strength_rank metadata."
        )
    if judge_size < target_size:
        raise ValueError(
            f"Configured judge '{judge_model}' ({judge_size:g}B) is smaller than "
            f"target '{target_model}' ({target_size:g}B)."
        )
    return True
