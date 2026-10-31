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
parser=argparse.ArgumentParser(); parser.add_argument('action');parser.add_argument('--environment');parser.add_argument('--profile');parser.add_argument('--output',required=True);parser.add_argument('--input');parser.add_argument('--previous');parser.add_argument('--current');parser.add_argument('--discovery');parser.add_argument('--require-stage');parser.add_argument('--snapshot');parser.add_argument('--require-complete',action='store_true');a=parser.parse_args()
with open(os.environ['TEST_ACTIONS'],'a') as log: log.write(a.action + '\n')
out=Path(a.output);out.mkdir();version=os.environ.get('TEST_VERSION','1.2.3.4');profile=os.environ.get('TEST_PROFILE','synthetic')
if a.action=='discover':
 if os.environ.get('TEST_MODE')=='discover-fail':
  write(out/'capture.json',{'sources':[{'name':'dependency-endpoints','status':'failed','failure':{'httpStatus':403},'reason':'SYNTHETIC_SECRET_DETAIL'}]});sys.exit(1)
 catalogue={'types':[{'componentType':1,'inUse':True,'definitions':[],'optionLabels':[{'source':'component-options'}]}]}
 write(out/'type-catalogue.json',catalogue)
 partial=os.environ.get('TEST_MODE')=='partial-discovery'
 write(out/'capture.json',{'profile':profile,'organizationVersion':version,'status':'partial' if partial else 'complete','inventoryComplete':not partial,'catalogue':{'path':'type-catalogue.json','sha256':sha((out/'type-catalogue.json').read_bytes())}})
 if partial:sys.exit(2)
elif a.action=='inventory':
 discovery=Path(a.input); reg=Path(__file__).with_name('handler-registry.json');status=json.loads(reg.read_text())['registrations'][0]['status']
 item={'componentType':1,'inUse':True,'identityStatus':'resolved','typeIdentity':'platform:1','handlers':{'export':{'status':status}}}
 counts={k:int(k==status) for k in ('supported','partial','unsupported','excluded','unregistered')}
 sdk=Path(__file__).with_name('sdk-component-contracts.json'); module=Path(__file__).with_name('platform_component_types.py')
 report={'schemaVersion':2,'classificationVersion':2,'typeCatalogueSha256':sha(sdk.read_bytes()),'kind':'component-inventory-report','profile':profile,'organizationVersion':version,'discoveryComplete':os.environ.get('TEST_MODE')!='partial-discovery','rawInventoryConsistency':{'solutionsMatch':True,'organizationVersionMatch':True,'claimedFlagsMatch':True},'types':[item],'totals':{'inUseTypes':1,'stageStatusesInUse':{'export':counts}}}
 if os.environ.get('TEST_MODE')=='forged-inventory':report['types'][0]['handlers']['export']['status']='partial'
 if os.environ.get('TEST_MODE')=='forged-identity':report['types'][0]['typeIdentity']='entity:forged'
 write(out/'inventory.json',report);write(out/'provenance.json',{'captureSha256':sha((discovery/'capture.json').read_bytes()),'catalogueSha256':sha((discovery/'type-catalogue.json').read_bytes()),'registrySha256':sha(reg.read_bytes()),'typeCatalogueSha256':sha(sdk.read_bytes()),'classificationModuleSha256':sha(module.read_bytes()),'classificationVersion':2})
 if os.environ.get('TEST_MODE')=='inventory-fail':print('SYNTHETIC_SECRET_DETAIL',file=sys.stderr);sys.exit(37)
 if status!='supported' or os.environ.get('TEST_MODE')=='partial-discovery':sys.exit(2)
elif a.action=='identity-coverage':
 discovery=Path(a.discovery);rules=Path(__file__).with_name('export-identity-rules.json');snap=Path(a.snapshot) if a.snapshot else None
 declared=json.loads(rules.read_text())['rules'][0]['status'];status='qualified' if snap and declared=='qualified' else 'partial';data_status='observed' if snap else 'unavailable'
 item={'componentType':1,'catalogueKey':'platform:1','identityStatus':'resolved','inUse':True,'declaredRuleStatus':declared,'ruleStatus':status,'dataStatus':data_status,'snapshotDocumentCount':1 if snap else 0}
 refs=[{'resolution':'resolved'}] if snap else []
 if snap and os.environ.get('TEST_MODE')=='forged-reference':refs=[{'resolution':'unresolved-external-or-missing'}]
 summary={'discoveredTypes':1,'inUseTypes':1,'ruleStatusesInUse':{status:1},'identityCount':1 if snap else 0,'referenceCount':len(refs),'unresolvedReferenceCount':0,'blockedDeclaredInUseCount':int(declared!='qualified')}
 report={'schemaVersion':1,'kind':'identity-coverage','profile':profile,'organizationVersion':version,'discoveryComplete':os.environ.get('TEST_MODE')!='partial-discovery','snapshot':{'provided':True,'verified':True,'profile':profile,'organizationVersion':version,'coverageComplete':True} if snap else None,'types':[item],'identities':[{'kind':'table'}] if snap else [],'references':refs,'diagnostics':[],'summary':summary,'rulesReady':declared=='qualified','referenceEvidenceComplete':bool(snap),'referenceCoverage':{'snapshot':{'status':'complete' if snap else 'not-evaluated'}},'complete':bool(snap)}
 if snap and os.environ.get('TEST_MODE')=='missing-reference-proof':report.pop('referenceEvidenceComplete')
 write(out/'identity-coverage.json',report);write(out/'provenance.json',{'discoveryCaptureSha256':sha((discovery/'capture.json').read_bytes()),'discoveryCatalogueSha256':sha((discovery/'type-catalogue.json').read_bytes()),'rulesSha256':sha(rules.read_bytes()),'snapshotManifestSha256':sha((snap/'manifest.json').read_bytes()) if snap else None,'snapshotCoverageSha256':sha((snap/'coverage.json').read_bytes()) if snap else None,'packageSha256':[]})
 if snap and (out.parent/'attestation.json').exists():
  att=json.loads((out.parent/'attestation.json').read_text());att.update({'discoverySha256':sha((discovery/'capture.json').read_bytes()),'inventorySha256':sha((out.parent/'inventory'/'inventory.json').read_bytes()),'identityCoverageSha256':sha((out/'identity-coverage.json').read_bytes()),'referenceClosure':'qualified'});write(out.parent/'attestation.json',att)
 if os.environ.get('TEST_MODE')=='partial-discovery':sys.exit(2)
elif a.action=='capture':
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
 write(out/'manifest.json',manifest);write(out/'coverage.json',{'complete':True,'componentTypes':[{'complete':True}],'sources':[{'family':'family','status':'complete'}],'inventoryConsistency':{'solutionsMatch':True,'organizationVersionMatch':True},'scopeTruncated':False});write(out/'provenance.json',{})
 if os.environ.get('TEST_MODE')!='no-attestation':
  files=[{'path':p.relative_to(out).as_posix(),'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size} for p in sorted(out.rglob('*')) if p.is_file()]
  att={'schemaVersion':1,'snapshotSha256':sha(canonical(files)),'profile':profile,'producerCommit':os.environ['TEST_PRODUCER_SHA'],'policySha256':os.environ['TEST_POLICY_HASH'],'sourceVersionBefore':version,'sourceVersionAfter':version,'familyCoverage':'complete','portability':'qualified','provenance':'qualified','publicSafety':'qualified'}
  if os.environ.get('TEST_MODE')=='attestation':att['snapshotSha256']='0'*64
  write(out.parent/'attestation.json',att)
elif a.action=='diff': write(out/'diff.json',{'changes':[]})
else: sys.exit(3)
