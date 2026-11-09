import sys
import os

# Ensure backend root is in sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Ensure writable SQLite database path on Vercel serverless runtime
if os.environ.get("VERCEL") or not os.environ.get("DATABASE_PATH"):
    os.environ.setdefault("DATABASE_PATH", "/tmp/trustlens.db")

from app.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
