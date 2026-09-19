"""Run only with the reviewed immutable release's own virtual environment."""
from pathlib import Path
import sys

# A source release is authoritative even if its venv also contains an older wheel.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from pdi.production_ops.cutover import main

if __name__ == '__main__':
    raise SystemExit(main())
