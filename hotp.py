import hmac

from hashlib import sha1

class HOTP:
    def __init__(self, key, step=1, dgst_algo=sha1, key_size=7):
        self.key = key
        self.algorithm = dgst_algo
        self.key_size = key_size
        self.step = step
        self.counter = 0

    def get_key(self):
        hashed_data = self._get_hash()
        
        truncated_data = self._dynamic_truncate(hashed_data)
        truncated_data = int.from_bytes(truncated_data, "big")

        return str(truncated_data % (10 ** self.key_size)).rjust(self.key_size, "0")

    def _step(self):
        while True:
            yield self.counter.to_bytes(64, "big")
            self.counter += step

    def _get_hash(self):
        next_step = next(self._step())
        if not isinstance(next_step, bytes):
            next_step = next_step.to_bytes(64, "big")
            
        return hmac.digest(self.key, next_step, self.algorithm)

    def _dynamic_truncate(self, hashed_data):
        offset = hashed_data[19] & 0xF

        return bytes([hashed_data[offset] & 0x7F,
                      hashed_data[offset+1] & 0xFF,
                      hashed_data[offset+2] & 0xFF,
                      hashed_data[offset+3] & 0xFF])
            
        
