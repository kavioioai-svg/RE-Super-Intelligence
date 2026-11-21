"""RE Super Intelligence (RESI) orchestration runtime.

Core modules are standard-library only so the runtime works inside any coding
agent's environment. The optional ``vision`` extra adds numpy for 3D analysis.
"""

__version__ = "0.3.0"

SECURITY_CLASSES = ("R", "L", "D", "M")
STATUSES = ("verified", "discovered", "unverified", "incompatible")
