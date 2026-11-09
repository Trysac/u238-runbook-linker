"""Allow running the CLI with ``python -m runbook_linker``."""

from __future__ import annotations

import sys

from runbook_linker import main

if __name__ == "__main__":
    sys.exit(main())
