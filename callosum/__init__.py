"""CALLOSUM: governed dual-hemisphere brain harness.

Inhibitory evidence-gated interhemispheric coupling + competence-profile-driven
functional reassignment on hemisphere loss, over a tamper-evident ledger.
"""
__version__ = "0.1.0"

from .adapter import HemisphereAdapter, MockHemisphere, TerminalHemisphere
from .bridge import Callosum
from .capability import CapabilityMatrix
from .corrections import CorrectionStore
from .envelope import BrainEnvelope
from .evidence import make_evidence, make_msg, validate_msg_evidence, validate_ref
from .failover import FailoverController, Heartbeat, Monitor, Quarantine, Watchdog
from .instrumentation import PositionTracker
from .ledger import Ledger
from .transport import FileDropBus, bump_epoch, get_epoch
