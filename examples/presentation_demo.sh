#!/usr/bin/env bash
set -uo pipefail
# scan and block intentionally exit 1 when the fixture is detected.
python -m redactgate.cli scan examples/presentation-input.txt --json
python -m redactgate.cli mask --style label < examples/presentation-input.txt
python -m redactgate.cli mask --rules examples/presentation-block.yaml < examples/presentation-input.txt
