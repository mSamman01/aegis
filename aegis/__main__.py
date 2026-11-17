"""Lets you run the tool as:  python -m aegis <command>"""

import sys

from aegis.cli import main

if __name__ == "__main__":
    sys.exit(main())
