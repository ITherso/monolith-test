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


__all__ = [
    'chain_bp',
    'cicd_bp',
    'byovd_bp',
    'stego_bp',
    'bitb_bp',
    'spray_bp',
]