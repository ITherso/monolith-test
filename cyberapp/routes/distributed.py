# cyberapp/routes/distributed.py
from flask import Blueprint, render_template
from cyberapp.models.db import db_conn

distributed_bp = Blueprint('distributed', __name__, template_folder='templates')

@distributed_bp.route('/distributed/<int:scan_id>')
def distributed_dashboard(scan_id):
    # DB'den deploy log'ları çek (intel tablosundan veya yeni tablo)
    with db_conn() as conn:
        logs = conn.execute(
            "SELECT data FROM intel WHERE scan_id = ? AND type LIKE '%DISTRIBUTED%'",
            (scan_id,)
        ).fetchall()
    logs = [log[0] for log in logs]
    
    return render_template('distributed.html', scan_id=scan_id, logs=logs)
