# Route blueprints package.
from cyberapp.routes.chain import bp as chain_bp

# Pro Feature Routes
try:
    from cyberapp.routes.cicd_jacker import cicd_bp
except ImportError:
    cicd_bp = None

try:
    from cyberapp.routes.byovd import byovd_bp
except ImportError:
    byovd_bp = None

try:
    from cyberapp.routes.stego_c2 import stego_bp
except ImportError:
    stego_bp = None

try:
    from cyberapp.routes.bitb_phishing import bitb_bp
except ImportError:
    bitb_bp = None

try:
    from cyberapp.routes.smart_spray import spray_bp
except ImportError:
    spray_bp = None

try:
    from cyberapp.routes.orbital_rf_warfare import orbital_rf_bp
except ImportError:
    orbital_rf_bp = None

try:
    from cyberapp.routes.scada_ics_hunter import scada_bp
except ImportError:
    scada_bp = None

try:
    from cyberapp.routes.automotive_canbus import automotive_bp
except ImportError:
    automotive_bp = None


__all__ = [
    'chain_bp',
    'cicd_bp',
    'byovd_bp',
    'stego_bp',
    'bitb_bp',
    'spray_bp',
    'orbital_rf_bp',
    'scada_bp',
    'automotive_bp',
]