import sqlite3

conn = sqlite3.connect('monolith_supreme.db')
cursor = conn.cursor()

# Create scans table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        date TEXT DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'PENDING',
        user_id TEXT DEFAULT 'anonymous'
    )
''')

# Create vulns table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        url TEXT,
        fix TEXT,
        severity TEXT DEFAULT 'MEDIUM',
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create intel table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS intel (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        data TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create techno table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS techno (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        detected_via TEXT,
        confidence INTEGER DEFAULT 80,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create tool_logs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS tool_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        output TEXT,
        execution_time REAL,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create gamification table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS gamification (
        scan_id INTEGER PRIMARY KEY,
        user_id TEXT NOT NULL,
        score INTEGER DEFAULT 0,
        xp INTEGER DEFAULT 0,
        level INTEGER DEFAULT 1,
        achievements TEXT,
        badges TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create blockchain_evidence table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS blockchain_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        tx_hash TEXT UNIQUE,
        evidence_hash TEXT,
        merkle_root TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        verified BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create cloud_findings table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS cloud_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        service TEXT,
        finding TEXT,
        severity TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create api_endpoints table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS api_endpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        url TEXT,
        method TEXT,
        status INTEGER,
        parameters TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create phishing_campaigns table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS phishing_campaigns (
        id TEXT PRIMARY KEY,
        name TEXT,
        targets TEXT,
        link TEXT,
        clicks INTEGER DEFAULT 0,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create scan_progress table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_progress (
        scan_id INTEGER PRIMARY KEY,
        progress INTEGER DEFAULT 0,
        eta_seconds INTEGER DEFAULT NULL,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create audit_logs table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        role TEXT,
        action TEXT,
        detail TEXT,
        ip TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        role TEXT DEFAULT 'analyst',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create exploits table (surum -> exploit eslestirmesi icin)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS exploits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve TEXT NOT NULL,
                    name TEXT NOT NULL,
                    product_key TEXT,
                    product_name TEXT,
        version_range TEXT,
        severity TEXT DEFAULT 'HIGH',
        exploit_type TEXT,
        description TEXT,
        "references" TEXT,
        extra_urls TEXT,
        source TEXT DEFAULT 'seed'
    )
''')

# Create scan_fingerprints table (tespit edilen teknoloji/surum)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        product_key TEXT NOT NULL,
        product_name TEXT,
        version TEXT,
        detected_via TEXT,
        evidence TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
    )
''')

# Create matched_exploits table (surume gore eslesen oto-exploit sonuclari)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS matched_exploits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        exploit_id INTEGER,
        cve TEXT,
        name TEXT,
        product_key TEXT,
        version TEXT,
        severity TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE,
        FOREIGN KEY (exploit_id) REFERENCES exploits (id) ON DELETE CASCADE
    )
''')

# Create feed_state table (besleme senkron durum takibi)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS feed_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT UNIQUE NOT NULL,
        last_sync TEXT,
        last_count INTEGER DEFAULT 0,
        last_status TEXT,
        etag TEXT,
        lastmod TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create authorized_targets table (oto-exploit kapsam kapisi)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS authorized_targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT UNIQUE NOT NULL,
        authorized_by TEXT,
        note TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
''')

# Create indexes
cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_product ON exploits(product_key)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_exploits_source ON exploits(source)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_fingerprints_scan ON scan_fingerprints(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_matched_scan ON matched_exploits(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulns(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_logs_scan_id ON tool_logs(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_blockchain_scan_id ON blockchain_evidence(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_cloud_scan ON cloud_findings(scan_id)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_scan ON api_endpoints(scan_id)")

conn.commit()
conn.close()
print("✓ Database tables created successfully!")
