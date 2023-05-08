from hotp import HOTP
import time

class TOTP(HOTP):
    def __init__(self, key, initial_ts, step=30, **kwargs):
        super(TOTP, self).__init__(key, step, *kwargs)
        self.counter = initial_ts

    def _step(self):
        while True:
            now = time.monotonic()
            yield int((now - self.counter) / self.step)
