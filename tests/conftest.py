import os
import sys
from pathlib import Path

os.environ["SENTINEL_ENVIRONMENT"] = "test"
sys.path.insert(0, str(Path(__file__).parents[1] / "apps" / "api" / "src"))
