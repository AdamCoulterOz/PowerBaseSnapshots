"""Synthetic producer: emits no real platform content or network traffic."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

def canonical(x): return (json.dumps(x, sort_keys=True, separators=(',', ':'))+'\n').encode()
def write(p,x): p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(canonical(x))
def sha(b): return hashlib.sha256(b).hexdigest()
parser=argparse.ArgumentParser(); parser.add_argument('action');parser.add_argument('--environment');parser.add_argument('--profile');parser.add_argument('--output',required=True);parser.add_argument('--input');parser.add_argument('--previous');parser.add_argument('--current');a=parser.parse_args()
with open(os.environ['TEST_ACTIONS'],'a') as log: log.write(a.action + '\n')
out=Path(a.output);out.mkdir();version=os.environ.get('TEST_VERSION','1.2.3.4');profile=os.environ.get('TEST_PROFILE','synthetic')
if a.action=='capture':
 (out/'raw-private.txt').write_text('SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD')
 pages=[]
 for name in ('organization-version-before','organization-version-after'):
  p=out/(name+'.json');write(p,{'Version':version});pages.append({'name':name,'status':'complete','pages':[{'path':p.name,'sha256':sha(p.read_bytes())}]})
 write(out/'capture.json',{'schemaVersion':1,'profile':profile,'status':'complete','fullConfigurationComplete':True,'organizationVersion':version,'inventoryConsistency':{'solutionsMatch':True,'organizationVersionMatch':True},'sources':pages})
 if os.environ.get('TEST_MODE')=='capture-partial': sys.exit(2)
elif a.action=='normalize':
 data=out/'family'/'one.json';write(data,{'id':'stable','value':1})
 path='family/one.json'
 if os.environ.get('TEST_MODE')=='symlink': data.unlink();data.symlink_to('/etc/hosts')
 if os.environ.get('TEST_MODE')=='escape': path='../outside.json'
 manifest={'schemaVersion':1,'profile':profile,'organizationVersion':version,'complete':True,'documents':[{'path':path,'family':'family','sha256':sha(data.read_bytes())}]}
 if os.environ.get('TEST_MODE')=='hash':manifest['documents'][0]['sha256']='0'*64
 write(out/'manifest.json',manifest);write(out/'coverage.json',{'complete':True,'componentTypes':[{'complete':True}],'sources':[{'status':'complete'}],'inventoryConsistency':{'solutionsMatch':True,'organizationVersionMatch':True},'scopeTruncated':False});write(out/'provenance.json',{})
 if os.environ.get('TEST_MODE')!='no-attestation':
  files=[{'path':p.relative_to(out).as_posix(),'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(out.rglob('*')) if p.is_file()]
  att={'schemaVersion':1,'snapshotSha256':sha(canonical(files)),'profile':profile,'producerCommit':os.environ['TEST_PRODUCER_SHA'],'policySha256':os.environ['TEST_POLICY_HASH'],'sourceVersionBefore':version,'sourceVersionAfter':version,'familyCoverage':'complete','portability':'qualified','provenance':'qualified','publicSafety':'qualified'}
  if os.environ.get('TEST_MODE')=='attestation':att['snapshotSha256']='0'*64
  write(out.parent/'attestation.json',att)
elif a.action=='diff': write(out/'diff.json',{'changes':[]})
else: sys.exit(3)
