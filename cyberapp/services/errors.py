from uuid import uuid4

from flask import g, jsonify, request

from cyberapp.services.logger import get_logger


def register_error_handlers(app):
    logger = get_logger("monolith.http")

    @app.before_request
    def _log_request():
        request_id = request.headers.get("X-Request-ID", str(uuid4()))
        g.request_id = request_id
        logger.info("request %s %s", request.method, request.path)

    @app.after_request
    def _log_response(response):
        logger.info("response %s %s %s", request.method, request.path, response.status_code)
        response.headers["X-Request-ID"] = getattr(g, "request_id", "-")
        return response

    @app.errorhandler(404)
    def not_found(error):
        if _wants_json():
            return jsonify({"error": "not_found"}), 404
        return "<h3>Not Found</h3>", 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("internal_error")
        if _wants_json():
            return jsonify({"error": "internal_error"}), 500
        return "<h3>Internal Server Error</h3>", 500

    @app.errorhandler(Exception)
    def unhandled_error(error):
        logger.exception("unhandled_error")
        if _wants_json():
            return jsonify({"error": "unexpected_error"}), 500
        return "<h3>Unexpected Error</h3>", 500


def _wants_json():
    if request.path.startswith("/scan_status") or request.path.startswith("/phishing/stats"):
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept
