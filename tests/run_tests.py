"""Run the full Sentinel test suite.

Usage:
    python tests/run_tests.py        # full suite
    python tests/run_tests.py -v     # verbose
    python tests/run_tests.py TestAuth.test_first_user_becomes_admin   # one test
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(argv=None):
    argv = argv or sys.argv[1:]
    verbosity = 2 if "-v" in argv or "--verbose" in argv else 1
    filt = [a for a in argv if not a.startswith("-")]

    loader = unittest.TestLoader()
    if filt:
        # allow `python run_tests.py TestAuth.test_login_returns_csrf`
        suite = unittest.TestSuite()
        for name in filt:
            for mod in ("test_auth", "test_security", "test_intel_alerts_rag"):
                try:
                    suite.addTests(loader.loadTestsFromName(mod + "." + name))
                except Exception:
                    pass
    else:
        suite = loader.discover(HERE, pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
