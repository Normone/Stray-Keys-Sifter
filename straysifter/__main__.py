"""python -m straysifter → CLI."""
import sys
from .frontends.cli import main

if __name__ == "__main__":
    sys.exit(main())