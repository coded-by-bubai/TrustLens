import sys
import os

# 1. Add backend directory to sys.path so 'app' package is discoverable
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.abspath(os.path.join(current_dir, "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# 2. Ensure writable database directory on Vercel serverless runtime
if os.environ.get("VERCEL") or not os.environ.get("DATABASE_PATH"):
    os.environ.setdefault("DATABASE_PATH", "/tmp/trustlens.db")

# 3. Import the FastAPI application
from app.main import app

# 4. Vercel Python Runtime supports ASGI 'app' directly, and 'handler' via Mangum
try:
    from mangum import Mangum
    handler = Mangum(app)
except Exception:
    handler = app
