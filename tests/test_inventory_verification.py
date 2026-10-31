"""Independent checks for versioned inventory classification evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('controller',ROOT/'pipeline/run.py')
controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True))
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

class InventoryVerification(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.discovery=self.root/'discovery';self.inv=self.root/'inventory';self.producer=self.root/'producer'
        self.tools=self.producer/'tools/PowerSpec.Baseline';self.tools.mkdir(parents=True)
        write(self.tools/'sdk-component-contracts.json',{'synthetic':True})
        (self.tools/'platform_component_types.py').write_text('# fixture')
        write(self.tools/'handler-registry.json',{'schemaVersion':2,'registrations':[]})
        self.code=15;self.entry={'componentType':15,'inUse':True,'definitions':[],'optionLabels':[]}
        self.evidence={'sdkName':controller.SDK_FALLBACK[15], 'sdk':{**controller.SDK_EVIDENCE,'typeCatalogueSha256':digest(self.tools/'sdk-component-contracts.json')}}
        self.report={'schemaVersion':2,'classificationVersion':2,'kind':'component-inventory-report','profile':'test','organizationVersion':'1.2.3.4','discoveryComplete':True,'rawInventoryConsistency':{'solutionsMatch':True,'organizationVersionMatch':True,'claimedFlagsMatch':True},'types':[{'componentType':15,'inUse':True,'identityStatus':'resolved','typeIdentity':'platform:15','identityEvidence':self.evidence,'handlers':{'export':{'status':'unregistered'}}}], 'totals':{'inUseTypes':1,'stageStatusesInUse':{'export':{'supported':0,'partial':0,'unsupported':0,'excluded':0,'unregistered':1}}}}
        self.persist()
    def tearDown(self): self.temp.cleanup()
    def persist(self):
        write(self.discovery/'type-catalogue.json',{'types':[self.entry]})
        write(self.discovery/'capture.json',{'profile':'test','organizationVersion':'1.2.3.4','status':'complete','inventoryComplete':True,'catalogue':{'path':'type-catalogue.json','sha256':digest(self.discovery/'type-catalogue.json')}})
        write(self.inv/'inventory.json',self.report)
        write(self.inv/'provenance.json',{'captureSha256':digest(self.discovery/'capture.json'),'catalogueSha256':digest(self.discovery/'type-catalogue.json'),'registrySha256':digest(self.tools/'handler-registry.json'),'typeCatalogueSha256':digest(self.tools/'sdk-component-contracts.json'),'classificationModuleSha256':digest(self.tools/'platform_component_types.py'),'classificationVersion':2})
    def verify(self): return controller.verify_inventory(self.discovery,self.inv,self.producer,{'profile':'test'},'1.2.3.4')
    def test_reviewed_fallback_and_unregistered_gate(self):
        _,counts,ready=self.verify();self.assertFalse(ready);self.assertEqual(counts['unregistered'],1)
    def test_unknown_and_registered_collision(self):
        self.assertEqual(controller._catalogue_identity({'componentType':99999,'definitions':[],'optionLabels':[]},'TEST'),('local:test:99999','unresolved'))
        definition={'name':'x','primaryEntityName':'appmodule','entityResolution':'matched','entityDefinitions':[{'logicalName':'appmodule'}]}
        self.assertEqual(controller._catalogue_identity({'componentType':80,'definitions':[definition],'optionLabels':[]},'test'),(None,'ambiguous'))
    def test_forged_name_is_rejected(self):
        self.evidence['sdkName']='Forged';self.persist()
        with self.assertRaises(controller.Hold):self.verify()
    def test_sdk_provenance_drift_is_rejected(self):
        (self.tools/'sdk-component-contracts.json').write_text('{"changed":true}')
        with self.assertRaises(controller.Hold):self.verify()
    def test_old_classification_rejected(self):
        self.report['classificationVersion']=1;self.persist()
        with self.assertRaises(controller.Hold):self.verify()
    def test_enum_hash_tampering_rejected(self):
        self.evidence['sdk']['decompiledSourceSha256']='0'*64;self.persist()
        with self.assertRaises(controller.Hold):self.verify()
if __name__=='__main__':unittest.main()
