import os
import queue
import threading
import uuid

from cyberapp.services.logger import get_logger

logger = get_logger("monolith.queue")
_job_queue = queue.Queue()
_worker_started = False
_lock = threading.Lock()
_backend = None


def _worker_loop():
    while True:
        job_id, func, args, kwargs = _job_queue.get()
        try:
            logger.info("job_started id=%s func=%s", job_id, getattr(func, "__name__", "callable"))
            func(*args, **kwargs)
            logger.info("job_finished id=%s", job_id)
        except Exception:
            logger.exception("job_failed id=%s", job_id)
        finally:
            _job_queue.task_done()


def ensure_worker():
    global _worker_started, _backend
    with _lock:
        if _worker_started:
            return
        backend = os.getenv("MONOLITH_QUEUE", "local").lower()
        if backend == "rq":
            try:
                import redis  # type: ignore
                import rq  # type: ignore

                _backend = (redis, rq)
                logger.info("using rq backend")
                _worker_started = True
                return
            except Exception:
                logger.warning("rq backend not available, falling back to local")
        thread = threading.Thread(target=_worker_loop, daemon=True)
        thread.start()
        _worker_started = True


def enqueue_job(func, *args, **kwargs):
    ensure_worker()
    if _backend:
        redis, rq = _backend
        conn = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        q = rq.Queue("monolith", connection=conn)
        job = q.enqueue(func, *args, **kwargs)
        return job.get_id()
    job_id = uuid.uuid4().hex
    _job_queue.put((job_id, func, args, kwargs))
    return job_id
