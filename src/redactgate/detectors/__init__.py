"""Detection layer — checksum validators + China-PII recognizers.

This subpackage is the m1 core of RedactGate: turn a blob of outbound text into
a list of checksum-confirmed :class:`Detection` records. Two layers:

- :mod:`redactgate.detectors.checksum` — pure GB 11643 / Luhn / GB 32100
  validators, no regex.
- :mod:`redactgate.detectors.cn_pii` — recognizers (regex candidate finder +
  checksum gate) and the public :func:`detect` / :func:`scan_text` entry points.

The redactor and ``redactgate scan`` build on top of this; nothing here imports
them, so the detection layer stays independently testable and reusable as a
library::

    from redactgate.detectors import scan_text
    for hit in scan_text(open("leaky.py").read()):
        print(hit.type, hit.line, hit.col, hit.checksum_valid)
"""

from __future__ import annotations

from .checksum import (
    is_valid_bank_card,
    is_valid_id_card,
    is_valid_uscc,
    luhn_valid,
)
from .cn_pii import (
    RECOGNIZERS,
    Detection,
    Recognizer,
    detect,
    scan_text,
)

__all__ = [
    # detection primitive + recognizers
    "Detection",
    "Recognizer",
    "RECOGNIZERS",
    "detect",
    "scan_text",
    # checksum validators
    "is_valid_id_card",
    "is_valid_bank_card",
    "is_valid_uscc",
    "luhn_valid",
]
