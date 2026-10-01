import os
import sys

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log-analyzer-agent")
sys.path.insert(0, BASE_DIR)
os.chdir(BASE_DIR)

from api_optimized import app

if __name__ == "__main__":
    app.run()
