# --- ERROR HANDLING MODULE ---
import datetime
import logging
import secrets
import time


class ErrorHandler:
    def __init__(self, log_file=None):
        self.logger = logging.getLogger("MonolithErrorHandler")
        self.logger.setLevel(logging.ERROR)
        if log_file:
            handler = logging.FileHandler(log_file)
        else:
            handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        if not self.logger.handlers:
            self.logger.addHandler(handler)

    def log_error(self, error, context=None):
        msg = f"{error}"
        if context:
            msg += f" | Context: {context}"
        self.logger.error(msg)


def safe_execute(func, error_message="Bir hata olustu", default_return=None):
    try:
        return func()
    except Exception as e:
        print(f"[!] {error_message}: {str(e)}")
        return default_return


def format_error_response(error, include_details=False):
    error_types = {
        "connection": "Hedef sunucuya baglanilamiyor. URL'yi kontrol edin.",
        "timeout": "Islem zaman asimina ugradi. Tekrar deneyin.",
        "permission": "Bu islem icin yetkiniz yok.",
        "not_found": "Istenen kaynak bulunamadi.",
        "invalid_input": "Gecersiz giris verisi. Kontrol edin.",
        "network": "Ag hatasi. Internet baglantinizi kontrol edin.",
        "tool_missing": "Gerekli arac bulunamadi. Kurulumu kontrol edin.",
        "database": "Veritabani hatasi. Tekrar deneyin.",
    }

    error_type = "unknown"
    error_lower = str(error).lower()

    for key in error_types:
        if key in error_lower:
            error_type = key
            break

    response = {
        "status": "error",
        "error_type": error_type,
        "message": error_types.get(error_type, "Bilinmeyen bir hata olustu."),
        "timestamp": datetime.datetime.now().isoformat(),
    }

    if include_details:
        response["details"] = str(error)

    return response


class EnhancedErrorHandler:
    """Gelistirilmis hata yonetim sistemi."""

    def __init__(self):
        self.error_log = []
        self.error_counts = {}

    def log_error(self, error, context=None, severity="MEDIUM"):
        error_id = f"ERR_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}"

        error_entry = {
            "id": error_id,
            "error": str(error),
            "context": context,
            "severity": severity,
            "timestamp": datetime.datetime.now().isoformat(),
        }

        self.error_log.append(error_entry)

        error_type = type(error).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        severity_prefix = {
            "LOW": "[LOW]",
            "MEDIUM": "[MEDIUM]",
            "HIGH": "[HIGH]",
            "CRITICAL": "[CRITICAL]",
        }

        print(f"\n{severity_prefix.get(severity, '[INFO]')} [{error_id}] {error_type}: {str(error)}")
        if context:
            print(f"   Context: {context}")

        return error_id

    def get_error_stats(self):
        return {
            "total_errors": len(self.error_log),
            "error_counts": self.error_counts,
            "recent_errors": self.error_log[-10:],
        }

    def handle_with_recovery(self, func, recovery_callback=None, max_retries=3):
        retries = 0
        last_error = None

        while retries < max_retries:
            try:
                return func()
            except Exception as e:
                last_error = e
                retries += 1
                self.log_error(e, context=f"Retry {retries}/{max_retries}")

                if recovery_callback:
                    recovery_callback(retries, e)

                if retries < max_retries:
                    time.sleep(2 ** retries)

        return safe_execute(lambda: None, f"Fonksiyon basarisiz oldu: {func.__name__}", None)
