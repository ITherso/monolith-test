import sys
import warnings
from pathlib import Path

# Ensure repo root is on sys.path when tests are run from outside the project.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

warnings.filterwarnings("ignore", category=ResourceWarning)
