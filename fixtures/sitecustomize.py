"""Replace the sentinel HTTP exchange with deterministic local fixture data."""
import io
import json
import os
from pathlib import Path
import urllib.request

class Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class Opener:
    def open(self, request, timeout=None):
        counter = Path(os.environ['TEST_SENTINEL_CALLS'])
        n = int(counter.read_text()) if counter.exists() else 0
        counter.write_text(str(n + 1))
        versions = os.environ['TEST_SENTINEL_VERSIONS'].split(',')
        return Response(json.dumps({'Version': versions[min(n, len(versions) - 1)]}).encode())

urllib.request.build_opener = lambda *args: Opener()
