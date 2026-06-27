import threading, time
class Account:
    def __init__(self):
        self.balance = 100.0
        self._lock = threading.Lock()
    def withdraw(self, amount):
        # SAFE: properly locked
        with self._lock:
            if self.balance >= amount:
                self.balance -= amount
                return True
            return False
