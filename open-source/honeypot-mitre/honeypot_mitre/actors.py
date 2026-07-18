"""Deterministic actor classification and behavioral overrides.

A coarse actor guess is derived from command volume, then corrected by two
deterministic behavioral rules ported verbatim from the original pipeline. Both
rules change the **label only** — they never touch the threat score.

Rules:

1. **Outlaw / Dota ("mdrfckr") worm signature.** If a session's command blob
   contains both ``mdrfckr`` and ``authorized_keys``, label it ``botnet_node``
   and tag it with the ``outlaw_mdrfckr_worm`` campaign indicator. This is the
   fixed SSH-key-persistence signature of that worm family.

2. **Sub-15s scripted session.** If a session ran at least one command and
   opened-and-closed in under 15 seconds, demote any ``human_operator`` guess to
   ``botnet_node`` — that timing is machine-driven, not hands-on-keyboard.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _coerce_float(value: Any) -> float:
    """Best-effort coercion to ``float`` (``0.0`` on failure)."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def baseline_actor_label(commands: List[str]) -> str:
    """Return the volume-based baseline actor guess.

    Mirrors the original rule: more than 5 commands looks hands-on
    (``human_operator``); otherwise it looks like an ``automated_scanner``.

    Args:
        commands: Ordered list of command lines.

    Returns:
        ``'human_operator'`` or ``'automated_scanner'``.
    """
    return 'human_operator' if len(commands) > 5 else 'automated_scanner'


def classify_actor(
    commands: List[str],
    duration: Any = 0,
    actor_label: Optional[str] = None,
    campaign_indicators: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Apply the deterministic behavioral overrides to an actor label.

    Args:
        commands: Ordered list of command lines for the session.
        duration: Session duration in seconds (coerced; non-numeric -> 0).
        actor_label: Existing actor guess to correct. If ``None``, the
            volume-based baseline from :func:`baseline_actor_label` is used.
        campaign_indicators: Existing campaign-indicator list to extend. A new
            list is created if ``None``.

    Returns:
        A dict with the (possibly corrected) ``actor_label`` and the
        ``campaign_indicators`` list.
    """
    label = actor_label if actor_label is not None else baseline_actor_label(commands)
    indicators = list(campaign_indicators) if campaign_indicators else []
    duration_s = _coerce_float(duration)
    blob = '\n'.join(commands)

    # Rule 1: Outlaw / Dota ("mdrfckr") SSH-key persistence worm signature.
    if 'mdrfckr' in blob and 'authorized_keys' in blob:
        label = 'botnet_node'
        if 'outlaw_mdrfckr_worm' not in indicators:
            indicators.append('outlaw_mdrfckr_worm')

    # Rule 2: ran commands and closed in under 15s -> scripted, demote human guess.
    if commands and 0 < duration_s < 15 and label == 'human_operator':
        label = 'botnet_node'

    return {
        'actor_label': label,
        'campaign_indicators': indicators,
    }
