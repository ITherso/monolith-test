# Route blueprints package.
from cyberapp.routes.chain import bp as chain_bp

# Pro Feature Routes
try:
    from cyberapp.routes.cicd_jacker import cicd_bp
except Exception:
    cicd_bp = None

try:
    from cyberapp.routes.byovd import byovd_bp
except Exception:
    byovd_bp = None

try:
    from cyberapp.routes.stego_c2 import stego_bp
except Exception:
    stego_bp = None

try:
    from cyberapp.routes.bitb_phishing import bitb_bp
except Exception:
    bitb_bp = None

try:
    from cyberapp.routes.smart_spray import spray_bp
except Exception:
    spray_bp = None

try:
    from cyberapp.routes.orbital_rf_warfare import orbital_rf_bp
except Exception:
    orbital_rf_bp = None

try:
    from cyberapp.routes.scada_ics_hunter import scada_bp
except Exception:
    scada_bp = None

try:
    from cyberapp.routes.automotive_canbus import automotive_bp
except Exception:
    automotive_bp = None

try:
    from cyberapp.routes.airgap_jumper import airgap_bp
except Exception:
    airgap_bp = None

try:
    from cyberapp.routes.blockchain_c2 import blockchain_c2_bp
except Exception:
    blockchain_c2_bp = None

try:
    from cyberapp.routes.apple_orchard import apple_orchard_bp
except Exception:
    apple_orchard_bp = None

try:
    from cyberapp.routes.edr_silencer import edr_silencer_bp
except Exception:
    edr_silencer_bp = None


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
    'airgap_bp',
    'blockchain_c2_bp',
    'apple_orchard_bp',
    'edr_silencer_bp',
]