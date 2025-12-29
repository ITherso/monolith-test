import re

from cyberapp.models.db import db_conn


class CloudSecurityAuditor:
    def __init__(self, target, scan_id):
        self.target = target
        self.scan_id = scan_id

    def log_finding(self, service, finding, severity="INFO"):
        try:
            with db_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO cloud_findings (scan_id, service, finding, severity)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.scan_id, service, finding, severity),
                )
        except Exception:
            pass

    def check_cloud_misconfigurations(self):
        domain = self.target.replace("https://", "").replace("http://", "").split("/")[0]

        if re.search(r'\.s3\.amazonaws\.com', domain) or re.search(r'\.s3-[a-z0-9-]+\.amazonaws\.com', domain):
            self.log_finding("AWS S3", "S3 bucket detected - check public access settings", "MEDIUM")

        if re.search(r'\.blob\.core\.windows\.net', domain):
            self.log_finding("Azure Blob", "Azure blob storage detected - verify ACLs", "MEDIUM")

        if re.search(r'\.storage\.googleapis\.com', domain) or re.search(r'\.commondatastorage\.googleapis\.com', domain):
            self.log_finding("GCP Storage", "GCP storage detected - check IAM permissions", "MEDIUM")

        self.log_finding("Cloud", "Cloud security audit completed", "INFO")

    def start(self):
        self.check_cloud_misconfigurations()
