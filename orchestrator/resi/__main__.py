"""Allow ``python -m resi``."""

import sys

from .adapters.inbound.cli import main

sys.exit(main())
