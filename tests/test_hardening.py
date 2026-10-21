import subprocess
import sys
import unittest

CODE = """
import ctypes, resource
from kpmergelib.hardening import harden_process
w = harden_process()
assert isinstance(w, list)
libc = ctypes.CDLL(None, use_errno=True)
print(libc.prctl(3, 0, 0, 0, 0), resource.getrlimit(resource.RLIMIT_CORE))
"""


class HardeningTest(unittest.TestCase):
    def test_harden_process(self):
        r = subprocess.run([sys.executable, "-c", CODE], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "0 (0, 0)")


if __name__ == "__main__":
    unittest.main()
