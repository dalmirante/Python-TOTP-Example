import os
import time

from totp import TOTP

totp = TOTP(os.urandom(20), time.monotonic())

while True:
    print(f"Your new key is {totp.get_key()}")
    
    time.sleep(30)
