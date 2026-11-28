"""The watcher as the sidecar runs it, see watcher.py: python3 -I on the
directory of the package, which the launcher mounts there alone and
read-only (see _start_watcher of processes.py). Python then has that
directory first on its path, and runs this file as no module of a
package: the package is taken from the directory above, which holds it
alone, for its modules to be what they are in the launcher. Run as a
module of the package, python -m, it is taken as it is."""

from __future__ import annotations

import importlib
import os
import sys

if __package__:
    from .watcher import main
else:
    package = os.path.abspath(sys.path[0])
    sys.path[0] = os.path.dirname(package)
    main = importlib.import_module(f"{os.path.basename(package)}.watcher").main

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
