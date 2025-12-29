import os

import redis  # type: ignore
import rq  # type: ignore


def main():
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    conn = redis.Redis.from_url(redis_url)
    queue = rq.Queue("monolith", connection=conn)
    worker = rq.Worker([queue], connection=conn)
    worker.work()


if __name__ == "__main__":
    main()
