import sys
from pathlib import Path

# Add analysis-service directory to sys.path
analysis_service_dir = Path(__file__).resolve().parent.parent
if str(analysis_service_dir) not in sys.path:
    sys.path.insert(0, str(analysis_service_dir))
