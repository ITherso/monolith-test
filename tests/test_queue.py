import threading
import time
import unittest

from cyberapp.services.queue import enqueue_job


class QueueTest(unittest.TestCase):
    def test_enqueue_executes_job(self):
        done = threading.Event()

        def _job():
            done.set()

        enqueue_job(_job)
        self.assertTrue(done.wait(timeout=2))


if __name__ == "__main__":
    unittest.main()
