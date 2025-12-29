try:
    from flask_socketio import SocketIO
except Exception:
    SocketIO = None


socketio = SocketIO(cors_allowed_origins="*", async_mode="threading") if SocketIO else None
