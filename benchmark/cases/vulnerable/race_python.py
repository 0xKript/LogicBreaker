from flask import Flask, request, jsonify
import time
app = Flask(__name__)

class Account:
    def __init__(self):
        self.balance = 100.0
    def withdraw(self, amount):
        # VULN: TOCTOU race condition
        if self.balance >= amount:
            time.sleep(0.02)
            self.balance -= amount
            return True
        return False
