"""Synthetic contained metadata stage for controller tests."""
import argparse
import json
import os
from pathlib import Path
import sys
p = argparse.ArgumentParser()
p.add_argument('command'); p.add_argument('--discovery', required=True)
p.add_argument('--environment', required=True); p.add_argument('--output', required=True)
a = p.parse_args()
if a.command != 'capture' or not (Path(a.discovery)/'capture.json').is_file(): sys.exit(1)
out = Path(a.output); out.mkdir()
failed = os.environ.get('TEST_MODE') == 'probe-partial'
source = {'family':'entity-metadata', 'status':'failed' if failed else 'complete',
          'name':'secret-identifier', 'reason':'private-path/host',
          'failure':{'httpStatus':403, 'requestPath':'private-host/path'}}
body = {'evidenceKind':'contained-component-evidence-v1', 'status':'partial' if failed else 'complete',
        'versionMatchesDiscovery':True, 'sources':[source]}
(out/'capture.json').write_text(json.dumps(body))
print('secret-url/identifier', file=sys.stderr)
sys.exit(2 if failed else 0)
