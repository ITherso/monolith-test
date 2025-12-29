import os
import logging

try:
    from celery import Celery
    HAS_CELERY = True
except Exception:
    Celery = None
    HAS_CELERY = False

BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
BACKEND_URL = os.getenv('CELERY_RESULT_BACKEND', BROKER_URL)

logger = logging.getLogger('monolith.celery')

if HAS_CELERY:
    celery = Celery('monolith', broker=BROKER_URL, backend=BACKEND_URL)
    celery.conf.update(task_serializer='json', accept_content=['json'], result_serializer='json')
else:
    # Minimal stub to allow importing when Celery is not installed.
    class _Stub:
        def task(self, *a, **kw):
            def deco(f):
                def wrapper(*args, **kwargs):
                    logger.warning('Celery not installed — running task synchronously: %s', f.__name__)
                    return f(*args, **kwargs)
                wrapper.delay = wrapper
                return wrapper
            return deco

    celery = _Stub()
