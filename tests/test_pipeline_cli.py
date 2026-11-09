"""Offline public coordinator checks. No Dataverse or GitHub access."""
import json
import hashlib
import shutil
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'pipeline' / 'run.py'


class PublicPipelineCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.work = self.root / 'private'
        self.work.mkdir()
        self.producer = self.root / 'producer'
        self.producer.mkdir()
        self.az_calls = self.root / 'az-calls'
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        az = bin_dir / 'az'
        az.write_text('#!/bin/sh\nprintf called >> "$TEST_AZ_CALLS"\nexit 87\n')
        az.chmod(0o755)
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''), TEST_AZ_CALLS=str(self.az_calls))
        self.config = self.root / 'config.json'

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, mode='check', config=None, producer=None, workdir=None):
        return subprocess.run([sys.executable, str(CLI), '--config', str(config or self.config), '--producer', str(producer or self.producer), '--workdir', str(workdir or self.work), '--mode', mode], capture_output=True, text=True, env=self.env)

    def test_clone_adds_missing_key_newline_without_exposing_it(self):
        spec=importlib.util.spec_from_file_location('pipeline_controller',CLI)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        expected='synthetic-key-material';observed=[]
        class Result:
            stdout='a'*40
        def fake_execute(args, cwd=None, env=None, allowed=(0,), phase=None):
            key=self.work/'deploy-key'
            if args[:2]==['git','clone']:
                observed.append((key.read_text(),key.stat().st_mode & 0o777,env['GIT_SSH_COMMAND']))
                Path(args[-1]).mkdir()
            result=Result()
            if args[:2]==['git','status']: result.stdout=''
            return result
        with patch.dict(os.environ,{'PRODUCER_SSH_KEY':expected}),patch.object(module,'execute',side_effect=fake_execute):
            module.clone_producer({'producerCommit':'a'*40},self.work)
        self.assertEqual(observed[0][0],expected+'\n')
        self.assertEqual(observed[0][1],0o600)
        self.assertIn('StrictHostKeyChecking=yes',observed[0][2])
        self.assertFalse((self.work/'deploy-key').exists())

    def test_oidc_token_exchange_refreshes_without_cli_and_scopes_dataverse(self):
        import io
        from urllib.parse import parse_qs, urlsplit
        spec=importlib.util.spec_from_file_location('oidc_pipeline',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        tenant='11111111-1111-1111-1111-111111111111';client='22222222-2222-2222-2222-222222222222';calls=[]
        class Response(io.BytesIO):
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def open(self,request,timeout):
                calls.append(request)
                if 'actions.githubusercontent.com' in request.full_url:return Response(b'{"value":"synthetic-assertion"}')
                return Response(b'{"access_token":"synthetic-access"}')
        settings={'POWERSPEC_AUTH_MODE':'github-oidc','POWERSPEC_AZURE_TENANT_ID':tenant,'POWERSPEC_AZURE_CLIENT_ID':client,'ACTIONS_ID_TOKEN_REQUEST_URL':'https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'synthetic-bearer'}
        with patch.dict(os.environ,settings,clear=True),patch.object(module.urllib.request,'build_opener',return_value=Opener()),patch.object(module,'execute',side_effect=AssertionError('CLI fallback')):
            for _ in range(2):self.assertEqual(module.token_for('https://synthetic.crm.dynamics.com'),'synthetic-access')
        self.assertEqual(len(calls),4)
        self.assertEqual(parse_qs(urlsplit(calls[0].full_url).query)['audience'],['api://AzureADTokenExchange'])
        self.assertEqual(calls[1].full_url,'https://login.microsoftonline.com/'+tenant+'/oauth2/v2.0/token')
        form=parse_qs(calls[1].data.decode());self.assertEqual(form['scope'],['https://synthetic.crm.dynamics.com/.default'])
        self.assertEqual(form['client_assertion'],['synthetic-assertion']);self.assertEqual(form['client_id'],[client])

    def test_oidc_rejects_untrusted_url_redirect_and_never_falls_back(self):
        spec=importlib.util.spec_from_file_location('oidc_pipeline_reject',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        settings={'POWERSPEC_AUTH_MODE':'github-oidc','POWERSPEC_AZURE_TENANT_ID':'11111111-1111-1111-1111-111111111111','POWERSPEC_AZURE_CLIENT_ID':'22222222-2222-2222-2222-222222222222','ACTIONS_ID_TOKEN_REQUEST_URL':'https://attacker.invalid/oidc','ACTIONS_ID_TOKEN_REQUEST_TOKEN':'secret-assertion-token'}
        with patch.dict(os.environ,settings,clear=True),patch.object(module,'execute',side_effect=AssertionError('CLI fallback')),patch.object(module.urllib.request,'build_opener',side_effect=AssertionError('network')):
            with self.assertRaises(module.Hold) as error:module.token_for('https://synthetic.crm.dynamics.com')
        self.assertNotIn('secret-assertion-token',str(error.exception))
        with self.assertRaises(module.Hold):module.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_version_query_renews_once_on_401_only(self):
        import io
        from urllib.error import HTTPError
        spec=importlib.util.spec_from_file_location('oidc_pipeline_401',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        class Response(io.BytesIO):
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def __init__(self,status):self.status=status;self.calls=[]
            def open(self,request,timeout):
                self.calls.append(request)
                if len(self.calls)==1:raise HTTPError(request.full_url,self.status,'private-detail',None,None)
                return Response(b'{"Version":"1.2.3.4"}')
        opener=Opener(401)
        with patch.object(module,'token_for',side_effect=['first','second']) as token,patch.object(module.urllib.request,'build_opener',return_value=opener):
            self.assertEqual(module.sentinel('https://synthetic.crm.dynamics.com'),'1.2.3.4')
            self.assertEqual(token.call_count,2)
        self.assertEqual([x.get_header('Authorization') for x in opener.calls],['Bearer first','Bearer second'])
        opener=Opener(403)
        with patch.object(module,'token_for',return_value='token') as token,patch.object(module.urllib.request,'build_opener',return_value=opener):
            with self.assertRaises(module.Hold) as error:module.sentinel('https://synthetic.crm.dynamics.com')
            self.assertEqual(token.call_count,1);self.assertNotIn('private-detail',str(error.exception))

    def test_oidc_identity_proof_checks_routes_identity_and_version(self):
        import io
        spec=importlib.util.spec_from_file_location('oidc_identity_test',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        user='33333333-3333-3333-3333-333333333333';client='22222222-2222-2222-2222-222222222222'
        class Response(io.BytesIO):
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        requests=[]
        class Opener:
            def open(self,request,timeout):
                requests.append(request);url=request.full_url
                if 'WhoAmI()' in url:body={'UserId':user}
                elif '/systemusers(' in url:body={'applicationid':client}
                elif 'EntityDefinitions(' in url:body={'LogicalName':'customcontrol','PrimaryIdAttribute':'customcontrolid'}
                elif 'RetrieveVersion()' in url:body={'Version':'1.2.3.4'}
                else:body={'value':[]}
                return Response(json.dumps(body).encode())
        with patch.dict(os.environ,{'POWERSPEC_AZURE_CLIENT_ID':client}),patch.object(module,'token_for',return_value='second-token') as token,patch.object(module.urllib.request,'build_opener',return_value=Opener()):
            module.oidc_identity_check('https://synthetic.crm.dynamics.com','1.2.3.4')
        token.assert_called_once_with('https://synthetic.crm.dynamics.com');self.assertEqual(len(requests),7)
        self.assertEqual([x.get_header('Authorization') for x in requests],['Bearer second-token']*7)
        urls=[x.full_url for x in requests]
        for route in ('WhoAmI()','systemusers(','msdyn_fileuploads','sdkmessageprocessingsteps','entitydatasources',"EntityDefinitions(LogicalName='customcontrol')",'RetrieveVersion()'):
            self.assertTrue(any(route in url for url in urls),route)

    def test_oidc_read_proof_rejects_wrong_identity_and_reports_status_only(self):
        import io
        from urllib.error import HTTPError
        spec=importlib.util.spec_from_file_location('oidc_identity_reject',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        user='33333333-3333-3333-3333-333333333333'
        class Response(io.BytesIO):
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def __init__(self,fail=False):self.fail=fail
            def open(self,request,timeout):
                if 'WhoAmI()' in request.full_url:return Response(json.dumps({'UserId':user}).encode())
                if '/systemusers(' in request.full_url:return Response(b'{"applicationid":"22222222-2222-2222-2222-222222222222"}')
                if self.fail:raise HTTPError(request.full_url,403,'sensitive-detail',None,None)
                raise AssertionError('Unexpected request')
        with patch.dict(os.environ,{'POWERSPEC_AZURE_CLIENT_ID':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}),patch.object(module,'token_for',return_value='secret-token'),patch.object(module.urllib.request,'build_opener',return_value=Opener()):
            with self.assertRaises(module.Hold) as error:module.oidc_identity_check('https://synthetic.crm.dynamics.com','1.2.3.4')
            self.assertNotIn(user,str(error.exception));self.assertNotIn('secret-token',str(error.exception))
        with patch.dict(os.environ,{'POWERSPEC_AZURE_CLIENT_ID':'22222222-2222-2222-2222-222222222222'}),patch.object(module,'token_for',return_value='secret-token'),patch.object(module.urllib.request,'build_opener',return_value=Opener(True)):
            with self.assertRaises(module.Hold) as error:module.oidc_identity_check('https://synthetic.crm.dynamics.com','1.2.3.4')
            self.assertIn('file uploads HTTP 403',str(error.exception));self.assertNotIn('sensitive-detail',str(error.exception));self.assertNotIn(user,str(error.exception))

    def test_oidc_read_proof_rejects_bad_shape_and_version_drift(self):
        import io
        spec=importlib.util.spec_from_file_location('oidc_shape_test',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        class Response(io.BytesIO):
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):self.close()
        class Opener:
            def __init__(self,bad):self.bad=bad
            def open(self,request,timeout):
                url=request.full_url
                if 'WhoAmI()' in url:body={'UserId':'33333333-3333-3333-3333-333333333333'}
                elif '/systemusers(' in url:body={'applicationid':'22222222-2222-2222-2222-222222222222'}
                elif 'EntityDefinitions(' in url:body={'LogicalName':'customcontrol','PrimaryIdAttribute':'customcontrolid'}
                elif 'RetrieveVersion()' in url:body={'Version':'1.2.3.5'}
                else:body={'value':{} if self.bad else []}
                return Response(json.dumps(body).encode())
        settings={'POWERSPEC_AZURE_CLIENT_ID':'22222222-2222-2222-2222-222222222222'}
        for bad,phrase in ((True,'invalid file uploads'),(False,'version changed')):
            with self.subTest(bad=bad),patch.dict(os.environ,settings),patch.object(module,'token_for',return_value='x'),patch.object(module.urllib.request,'build_opener',return_value=Opener(bad)):
                with self.assertRaises(module.Hold) as error:module.oidc_identity_check('https://synthetic.crm.dynamics.com','1.2.3.4')
                self.assertIn(phrase,str(error.exception))

    def test_auth_check_does_not_clone_producer_or_inspect_tags(self):
        import contextlib,io
        spec=importlib.util.spec_from_file_location('oidc_main_test',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.config.write_text(json.dumps({'schemaVersion':1,'producerRepository':'AdamCoulterOz/PowerSpec','profile':'synthetic'}))
        class Result:
            def __init__(self,out):self.stdout=out
        def git(args,**kwargs):
            if args[:2]==['git','status']:return Result('')
            if args[:2]==['git','branch']:return Result('main')
            raise AssertionError('Unexpected command')
        env={'SENTINEL_URL':'https://synthetic.crm.dynamics.com','POWERSPEC_AUTH_MODE':'github-oidc'}
        argv=[str(CLI),'--config',str(self.config),'--workdir',str(self.work),'--mode','auth-check']
        output=io.StringIO()
        with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',argv),patch.object(module,'execute',side_effect=git),patch.object(module,'sentinel',return_value='1.2.3.4'),patch.object(module,'oidc_identity_check') as identity,patch.object(module,'existing_tag',side_effect=AssertionError('Unexpected tag check')),patch.object(module,'clone_producer',side_effect=AssertionError('Unexpected clone')),contextlib.redirect_stdout(output):
            self.assertEqual(module.main(),0)
        identity.assert_called_once_with(env['SENTINEL_URL'],'1.2.3.4');self.assertIn('application identity matched',output.getvalue())

    def test_manifest_indexed_diff_and_tampered_prior(self):
        spec=importlib.util.spec_from_file_location('diff_pipeline',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        def tree(name,entries):
            root=self.root/name;root.mkdir();documents=[]
            for path,data in entries.items():
                target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
                documents.append({'path':path,'sha256':hashlib.sha256(data).hexdigest()})
            (root/'manifest.json').write_text(json.dumps({'schemaVersion':1,'documents':documents}))
            return root
        previous=tree('previous',{'stable.json':b'same','changed.json':b'old','removed.json':b'gone'})
        current=tree('current',{'stable.json':b'same','changed.json':b'new','added.json':b'added'})
        diff=module.snapshot_diff(previous,current,'synthetic','1.2.3.4')
        self.assertEqual([x['path'] for x in diff['added']],['added.json'])
        self.assertEqual([x['path'] for x in diff['removed']],['removed.json'])
        self.assertEqual([x['path'] for x in diff['changed']],['changed.json'])
        self.assertEqual(diff['changed'][0]['oldSha256'],hashlib.sha256(b'old').hexdigest())
        self.assertEqual(diff['changed'][0]['newSha256'],hashlib.sha256(b'new').hexdigest())
        self.assertNotEqual(diff['previousPublicSubtreeSha256'],diff['currentPublicSubtreeSha256'])
        empty=module.snapshot_diff(None,current,'synthetic','1.2.3.4');self.assertIsNone(empty['previousPublicSubtreeSha256']);self.assertEqual(len(empty['added']),3)
        same=module.snapshot_diff(current,current,'synthetic','1.2.3.4');self.assertEqual((same['added'],same['removed'],same['changed']),([],[],[]))
        (previous/'removed.json').write_bytes(b'tampered')
        with self.assertRaises(module.Hold):module.snapshot_diff(previous,current,'synthetic','1.2.3.4')

    def test_diff_rejects_unsafe_prior_manifest_and_symlink(self):
        spec=importlib.util.spec_from_file_location('diff_safety',CLI);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        old=self.root/'old';old.mkdir();new=self.root/'new';new.mkdir()
        (new/'manifest.json').write_text('{"schemaVersion":1,"documents":[]}')
        (old/'manifest.json').write_text(json.dumps({'schemaVersion':1,'documents':[{'path':'../secret','sha256':'0'*64}]}))
        with self.assertRaises(module.Hold):module.snapshot_diff(old,new,'synthetic','1.2.3.4')
        (old/'manifest.json').write_text('{"schemaVersion":1,"documents":[]}');(old/'link').symlink_to('/etc/hosts')
        with self.assertRaises(module.Hold):module.snapshot_diff(old,new,'synthetic','1.2.3.4')

    def test_help_does_not_invoke_azure_or_producer(self):
        result = subprocess.run([sys.executable, str(CLI), '--help'], capture_output=True, text=True, env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.az_calls.exists())



class PublicationFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.repo = self.root / 'publication'; self.remote = self.root / 'remote.git'
        self.git(None, 'init', '--bare', str(self.remote))
        self.git(None, 'clone', str(self.remote), str(self.repo))
        self.git(self.repo, 'config', 'user.name', 'Fixture')
        self.git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'README.md').write_text('synthetic public repository\n')
        self.git(self.repo, 'add', 'README.md'); self.git(self.repo, 'commit', '-m', 'initial'); self.git(self.repo, 'push', '-u', 'origin', 'HEAD')
        self.producer = self.root / 'producer'; self.producer.mkdir(); self.git(self.producer, 'init')
        self.git(self.producer, 'config', 'user.name', 'Fixture'); self.git(self.producer, 'config', 'user.email', 'fixture@example.invalid')
        cli = self.producer / 'tools/PowerSpec.Baseline/baseline.py'; cli.parent.mkdir(parents=True); shutil.copy(ROOT / 'fixtures/producer.py', cli)
        shutil.copy(ROOT / 'fixtures/contained_metadata_probe.py', cli.parent/'contained_components.py')
        (cli.parent/'sdk-component-contracts.json').write_text('{}')
        (cli.parent/'platform_component_types.py').write_text('# synthetic fixture\n')
        (cli.parent/'handler-registry.json').write_text(json.dumps({'schemaVersion':2,'registrations':[{'typeIdentity':'platform:1','stage':'export','status':'supported','verification':{'status':'passed','tests':['fixture']}}]}))
        (cli.parent/'export-identity-rules.json').write_text(json.dumps({'schemaVersion':1,'rules':[{'typeIdentity':'platform:1','status':'qualified','snapshotFamily':'family','verification':{'status':'passed','tests':['fixture']}}]}))
        (cli.parent/'public-projection-policy.json').write_text(json.dumps({'publicationApproved': True}))
        self.git(self.producer, 'add', '.'); self.git(self.producer, 'commit', '-m', 'synthetic producer')
        self.producer_sha = self.git(self.producer, 'rev-parse', 'HEAD').stdout.strip()
        policy={'policyVersion': 1, 'portableFamilies': ['family']}
        self.policy_sha=hashlib.sha256((cli.parent/'public-projection-policy.json').read_bytes()).hexdigest()
        self.config=self.root/'config.json';self.config.write_text(json.dumps({'schemaVersion':1,'producerRepository':'AdamCoulterOz/PowerSpec','producerCommit':self.producer_sha,'profile':'synthetic','approvedPolicySha256':self.policy_sha, **policy}))
        self.work=self.root/'private';self.work.mkdir()
        bindir=self.root/'bin';bindir.mkdir();az=bindir/'az';az.write_text("#!/bin/sh\nprintf called >> \"$TEST_AZ_CALLS\"\nprintf '%s' '{\"accessToken\":\"synthetic\"}'\n");az.chmod(0o755)
        self.env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ.get('PATH',''),PYTHONPATH=str(ROOT/'fixtures'),SENTINEL_URL='https://synthetic.crm.dynamics.com',TEST_SENTINEL_CALLS=str(self.root/'sentinel-calls'),TEST_SENTINEL_VERSIONS='1.2.3.4',TEST_VERSION='1.2.3.4',TEST_PROFILE='synthetic',TEST_PRODUCER_SHA=self.producer_sha,TEST_POLICY_HASH=self.policy_sha,TEST_AZ_CALLS=str(self.root/'az-calls'),TEST_ACTIONS=str(self.root/'actions'),POWERSPEC_AZURE_CLIENT_ID='11111111-1111-1111-1111-111111111111',POWERSPEC_INSTRUMENTATION_ROLE_ID='22222222-2222-2222-2222-222222222222',TEST_INSTRUMENTATION_CLIENT='11111111-1111-1111-1111-111111111111',TEST_INSTRUMENTATION_ROLE='22222222-2222-2222-2222-222222222222')

    def tearDown(self): self.tmp.cleanup()
    def git(self,cwd,*args): return subprocess.run(['git',*args],cwd=cwd,capture_output=True,text=True,check=True)
    def run_cli(self,mode='run'):
        return subprocess.run([sys.executable,str(CLI),'--config',str(self.config),'--workdir',str(self.work),'--producer',str(self.producer),'--mode',mode],cwd=self.repo,env=self.env,capture_output=True,text=True)
    def tags(self): return self.git(self.repo,'ls-remote','--tags','origin').stdout
    def test_qualified_publish_annotated_tag_and_repeat_is_noop(self):
        result=self.run_cli();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('refs/tags/service/1.2.3.4',self.tags())
        self.assertEqual(self.git(self.repo,'cat-file','-t','service/1.2.3.4').stdout.strip(),'tag')
        head=self.git(self.repo,'rev-parse','HEAD').stdout
        self.assertTrue((self.repo/'versions/synthetic/1.2.3.4.json').is_file())
        delta=json.loads((self.repo/'diffs/synthetic/1.2.3.4.json').read_text());self.assertIsNone(delta['previousPublicSubtreeSha256']);self.assertEqual([x['path'] for x in delta['added']],['family/one.json'])
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['acquire-baseline','finalize-publication'])
        self.assertNotIn('SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD', result.stdout + result.stderr)
        self.assertNotIn(self.env['POWERSPEC_AZURE_CLIENT_ID'], result.stdout + result.stderr)
        self.assertNotIn(self.env['POWERSPEC_INSTRUMENTATION_ROLE_ID'], result.stdout + result.stderr)
        files = self.git(self.repo,'ls-files').stdout
        self.assertNotIn('raw-private.txt', files)
        search=subprocess.run(['git','grep','-l','SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD','HEAD'],cwd=self.repo,capture_output=True,text=True)
        self.assertEqual(search.returncode,1)
        result=self.run_cli();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD').stdout,head)
    def test_publication_disables_commit_hook_and_publishes_exact_tree(self):
        hook = self.repo/'.git'/'hooks'/'pre-commit'
        hook.write_text('#!/bin/sh\nprintf injected > unapproved\ngit add unapproved\n')
        hook.chmod(0o755)
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.repo/'unapproved').exists())
        self.assertNotIn('unapproved', self.git(self.repo, 'ls-tree', '-r', '--name-only', 'HEAD').stdout)
        self.assertIn('refs/tags/service/1.2.3.4', self.tags())

    def test_unqualified_cases_hold_without_publication(self):
        for mode in ('capture-partial','no-attestation','attestation','hash','escape','symlink','unknown-scope','partial-gate','secretpath'):
            with self.subTest(mode=mode):
                self.env['TEST_MODE']=mode
                result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertEqual(self.tags(),'')
                self.assertNotIn('synthetic',result.stdout+result.stderr)
    def test_metadata_probe_runs_exact_stages_and_sanitizes_failure(self):
        self.env['TEST_MODE'] = 'probe-partial'
        result = self.run_cli('metadata-probe')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['discover'])
        self.assertIn('"family":"entity-metadata"', result.stdout)
        self.assertIn('"ordinal":1', result.stdout)
        self.assertIn('"httpStatus":403', result.stdout)
        for value in ('secret-identifier', 'private-host', 'private-path', 'secret-url'):
            self.assertNotIn(value, result.stdout + result.stderr)
        self.assertEqual(self.tags(), '')

    def test_partial_full_run_reports_safe_metadata_failure(self):
        self.env['TEST_MODE'] = 'capture-partial-metadata'
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('Metadata diagnostics:', result.stdout)
        self.assertIn('"httpStatus":403', result.stdout)
        self.assertNotIn('private-secret', result.stdout + result.stderr)
        self.assertNotIn('secret-host', result.stdout + result.stderr)
        self.assertEqual(self.tags(), '')

    def test_metadata_probe_complete_never_publishes(self):
        result = self.run_cli('metadata-probe')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"status":"complete"', result.stdout)
        self.assertEqual(self.tags(), '')
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['discover'])

    def test_missing_or_invalid_instrumentation_holds_before_capture(self):
        for value in ('', 'not-a-uuid', '00000000-0000-0000-0000-000000000000'):
            with self.subTest(value=value):
                self.env['POWERSPEC_INSTRUMENTATION_ROLE_ID'] = value
                result = self.run_cli()
                self.assertEqual(result.returncode, 2)
                self.assertIn('Instrumentation client and role configuration is missing or invalid.', result.stderr)
                self.assertFalse((self.root/'actions').exists())
                self.assertEqual(self.tags(), '')

    def test_different_expected_pair_holds_at_producer(self):
        self.env['TEST_INSTRUMENTATION_ROLE'] = '33333333-3333-3333-3333-333333333333'
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(self.env['POWERSPEC_INSTRUMENTATION_ROLE_ID'], result.stdout + result.stderr)
        self.assertEqual(self.tags(), '')

    def test_version_changed_during_capture_holds(self):
        self.env['TEST_SENTINEL_VERSIONS']='1.2.3.4,1.2.3.5'
        result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr);self.assertEqual(self.tags(),'')
    def test_unqualified_policy_still_monitors_and_run_holds(self):
        config=json.loads(self.config.read_text()); config['producerCommit']=None;config['approvedPolicySha256']=None;config['portableFamilies']=[]
        self.config.write_text(json.dumps(config))
        before=self.git(self.repo,'rev-parse','HEAD').stdout
        check=self.run_cli('check')
        self.assertEqual(check.returncode,0,check.stdout+check.stderr)
        self.assertIn('1.2.3.4',check.stdout)
        self.assertIn('not yet established',check.stdout)
        run=self.run_cli('run')
        self.assertEqual(run.returncode,2,run.stdout+run.stderr)
        self.assertIn('1.2.3.4',run.stdout)
        self.assertFalse((self.root/'actions').exists())
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD').stdout,before)
        self.assertEqual(self.tags(),'')

    def test_diagnose_runs_without_policy_or_publication_and_emits_only_counts(self):
        config=json.loads(self.config.read_text());config['approvedPolicySha256']=None;config['portableFamilies']=[]
        self.config.write_text(json.dumps(config))
        before=self.git(self.repo,'rev-parse','HEAD').stdout
        summary=self.root/'summary';self.env['GITHUB_STEP_SUMMARY']=str(summary)
        result=self.run_cli('diagnose')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['discover','inventory','identity-coverage'])
        self.assertIn('Reference completeness not evaluated',summary.read_text())
        self.assertNotIn('SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD',result.stdout+result.stderr+summary.read_text())
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD').stdout,before)
        self.assertEqual(self.tags(),'')

    def test_failed_discovery_reports_only_fixed_source_and_status(self):
        self.env['TEST_MODE']='discover-fail'
        result=self.run_cli('diagnose')
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('Stage: discovery.',result.stdout)
        self.assertIn('Discovery source dependency-endpoints: HTTP 403.',result.stdout)
        self.assertIn('Discovery failed (exit 1)',result.stderr)
        self.assertNotIn('SYNTHETIC_SECRET_DETAIL',result.stdout+result.stderr)
        self.assertEqual(self.tags(),'')

    def test_failed_inventory_identifies_phase_without_stderr(self):
        self.env['TEST_MODE']='inventory-fail'
        result=self.run_cli('diagnose')
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('Stage: inventory.',result.stdout)
        self.assertIn('Inventory failed (exit 37)',result.stderr)
        self.assertNotIn('SYNTHETIC_SECRET_DETAIL',result.stdout+result.stderr)
        self.assertEqual(self.tags(),'')

    def test_partial_discovery_preserves_diagnostic_but_holds(self):
        self.env['TEST_MODE']='partial-discovery'
        result=self.run_cli('diagnose');self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('Component inventory:',result.stdout)
        self.assertIn('Discovery diagnostics are incomplete',result.stderr)
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['discover','inventory','identity-coverage'])
        self.assertEqual(self.tags(),'')

    def test_existing_tag_does_not_skip_diagnose(self):
        self.git(self.repo,'tag','-a','service/1.2.3.4','-m','{}')
        self.git(self.repo,'push','origin','refs/tags/service/1.2.3.4')
        result=self.run_cli('diagnose')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['discover','inventory','identity-coverage'])

    def test_invalid_sentinel_origins_are_rejected_before_token_acquisition(self):
        for origin in ('https://example.com', 'http://synthetic.crm.dynamics.com', 'https://synthetic.crm.dynamics.com:443', 'https://user@synthetic.crm.dynamics.com', 'https://synthetic.crm.dynamics.com/path', 'https://synthetic.crm.dynamics.com?x=y', 'https://synthetic.crm.dynamics.com#x'):
            with self.subTest(origin=origin):
                self.env['SENTINEL_URL']=origin
                result=self.run_cli('check')
                self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertFalse((self.root/'sentinel-calls').exists())
                self.assertFalse((self.root/'az-calls').exists())
                self.assertFalse((self.root/'actions').exists())

    def test_wrong_policy_hash_holds_before_capture(self):
        config=json.loads(self.config.read_text());config['approvedPolicySha256']='0'*64
        self.config.write_text(json.dumps(config))
        result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertIn('1.2.3.4',result.stdout)
        self.assertFalse((self.root/'actions').exists());self.assertEqual(self.tags(),'')

    def test_atomic_push_rejection_does_not_publish_branch_or_tag(self):
        before = self.git(self.repo,'ls-remote','--heads','origin').stdout
        hook = self.remote/'hooks/pre-receive'
        hook.write_text('#!/bin/sh\nwhile read old new ref; do\n  case "$ref" in refs/tags/*) exit 1;; esac\ndone\nexit 0\n')
        hook.chmod(0o755)
        result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(self.git(self.repo,'ls-remote','--heads','origin').stdout,before)
        self.assertEqual(self.tags(),'')

    def test_existing_same_version_conflicting_tag_is_rejected(self):
        self.git(self.repo,'tag','-a','service/1.2.3.4','-m','{}')
        self.git(self.repo,'push','origin','refs/tags/service/1.2.3.4')
        head=self.git(self.repo,'rev-parse','HEAD').stdout
        result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD').stdout,head)
        self.assertFalse((self.root/'actions').exists())

    def test_new_version_with_same_configuration_has_version_record_and_tag(self):
        first=self.run_cli();self.assertEqual(first.returncode,0,first.stdout+first.stderr)
        self.env['TEST_SENTINEL_VERSIONS']='1.2.3.5';self.env['TEST_VERSION']='1.2.3.5'
        second=self.run_cli();self.assertEqual(second.returncode,0,second.stdout+second.stderr)
        self.assertIn('refs/tags/service/1.2.3.5',self.tags());self.assertTrue((self.repo/'versions/synthetic/1.2.3.5.json').is_file())
        delta=json.loads((self.repo/'diffs/synthetic/1.2.3.5.json').read_text());self.assertEqual((delta['added'],delta['removed'],delta['changed']),([],[],[]));self.assertEqual(delta['previousPublicSubtreeSha256'],delta['currentPublicSubtreeSha256'])


if __name__ == '__main__':
    unittest.main()

class AcquisitionFailureSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        spec = importlib.util.spec_from_file_location('failure_controller', CLI)
        self.controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.controller)

    def write_report(self, stages):
        (self.root / 'acquisition.json').write_text(json.dumps({
            'schemaVersion': 1, 'kind': 'private-baseline-acquisition-v1',
            'profile': 'secret-host/private-path', 'inputSha256': {}, 'stages': stages,
            'consistency': 'not-evaluated', 'fullConfigurationComplete': False,
            'publicationQualified': False}))

    def test_partial_stage_and_coverage_expose_only_allowlisted_facts(self):
        self.write_report([{'name': 'representation', 'status': 'partial', 'exitCode': 2},
                           {'name': 'coverage', 'status': 'blocked', 'dependencies': ['representation']}])
        (self.root / 'coverage').mkdir()
        gates = {name: False for name in self.controller.REQUIRED_GATES}
        (self.root / 'coverage' / 'coverage.json').write_text(json.dumps({
            'schemaVersion': 2, 'kind': 'baseline-coverage-v2', 'profile': 'secret',
            'organizationVersion': 'secret', 'types': [{'secret': 'private-path'}],
            'requiredGateResults': gates, 'diagnostics': {
                'dependencyOnlyAcquisition': 'secret', 'scopeUnresolvedMembershipRows': 3,
                'referenceClosure': 'secret', 'importReadiness': 'secret',
                'producerPublicProjectionQualified': False}, 'summary': {},
            'complete': False, 'interpretation': 'private-path'}))
        result = self.controller.acquisition_failure_summary(self.root)
        self.assertEqual(result['stages'], [{'stage': 'representation', 'status': 'partial', 'exitCode': 2},
                                            {'stage': 'coverage', 'status': 'blocked'}])
        self.assertEqual(result['requiredGateResults'], gates)
        self.assertEqual(result['counts'], {'scopeUnresolvedMembershipRows': 3})
        self.assertNotIn('secret', json.dumps(result))
        self.assertNotIn('private-path', json.dumps(result))

    def test_frozen_stage_manifest_schema_is_accepted(self):
        stages = [{'name': name, 'status': 'complete', 'exitCode': 0,
                   'reportSha256': 'a' * 64}
                  for name in sorted(self.controller.ACQUISITION_STAGES) if name != 'coverage']
        stages.append({'name': 'coverage', 'status': 'blocked',
                       'dependencies': ['projection-replay'], 'reason': 'missing hashed stage reports'})
        stages[0]['bundleSha256'] = 'b' * 64
        self.write_report(stages)
        report = json.loads((self.root / 'acquisition.json').read_text())
        report['nonmaterializationEvidence'] = {'private': 'ignored'}
        report['projectionReproducible'] = False
        report['instrumentationContextSha256'] = 'c' * 64
        (self.root / 'acquisition.json').write_text(json.dumps(report))
        result = self.controller.acquisition_failure_summary(self.root)
        self.assertEqual(result, {'status': 'incomplete', 'stages': [{'stage': 'coverage', 'status': 'blocked'}]})

    def test_hostile_and_unknown_fields_are_generic(self):
        for row in ({'name': 'https://private.example/path', 'status': 'failed', 'exitCode': 1},
                    {'name': 'coverage', 'status': 'failed', 'exitCode': 1, 'error': 'secret/path'},
                    {'name': 'coverage', 'status': 'failed', 'exitCode': 1, 'reason': 'secret/path'},
                    {'name': 'coverage', 'status': 'failed', 'exitCode': True}):
            with self.subTest(row=row):
                self.write_report([row])
                result = self.controller.acquisition_failure_summary(self.root)
                self.assertEqual(result, {'status': 'unavailable'})
                self.assertNotIn('secret', json.dumps(result))
        (self.root / 'acquisition.json').unlink()
        (self.root / 'acquisition.json').symlink_to('/etc/passwd')
        self.assertEqual(self.controller.acquisition_failure_summary(self.root), {'status': 'unavailable'})

class PublicationPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        spec = importlib.util.spec_from_file_location('preflight_controller', CLI)
        self.controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.controller)
        self.git('init', '-q'); self.git('config', 'user.name', 'Fixture'); self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root/'base').write_text('base'); self.git('add', 'base'); self.git('commit', '-qm', 'base')
        self.previous = self.git('rev-parse', 'HEAD').strip()
        self.snapshot = self.root/'baselines'/'profile'; self.snapshot.mkdir(parents=True)
        self.data = self.snapshot/'data.json'; self.data.write_bytes(b'approved data')
        self.support = self.root/'versions'/'evidence.json'; self.support.parent.mkdir(); self.support.write_bytes(b'approved evidence')
        self.allowed = ['baselines/profile', 'versions/evidence.json']
        self.attested = [{'path':'data.json', 'sha256':hashlib.sha256(b'approved data').hexdigest(), 'bytes':13}]

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, capture_output=True, text=True, check=True).stdout

    def verify(self):
        self.controller.verify_staged_publication(self.root, self.snapshot, self.attested,
                                                  {self.support:b'approved evidence'}, self.allowed)

    def test_staged_exact_bytes_and_index_tampering(self):
        self.git('add', '-A', '--', *self.allowed); self.verify()
        self.data.write_bytes(b'tampered data'); self.git('add', str(self.data.relative_to(self.root)))
        self.data.write_bytes(b'approved data')
        with self.assertRaises(self.controller.Hold): self.verify()

    def test_ignored_attested_file_fails_index_check(self):
        (self.root/'.gitignore').write_text('data.json\n')
        self.git('add', '-A', '--', *self.allowed)
        with self.assertRaises(self.controller.Hold): self.verify()

    def test_object_limit_holds(self):
        self.git('add', '-A', '--', *self.allowed)
        with patch.object(self.controller, 'MAX_GIT_BLOB_BYTES', 12):
            with self.assertRaises(self.controller.Hold): self.verify()

    def test_pack_measured_for_commit_and_tag_and_limit_holds(self):
        self.git('add', '-A', '--', *self.allowed); self.verify()
        self.git('commit', '-qm', 'snapshot'); self.git('tag', '-a', 'service/1.2.3.4', '-m', 'evidence')
        commit = self.git('rev-parse', 'HEAD').strip(); tag = self.git('rev-parse', 'refs/tags/service/1.2.3.4').strip()
        self.controller.verify_push_pack(self.root, self.previous, commit, tag)
        with patch.object(self.controller, 'MAX_PUSH_PACK_BYTES', 1):
            with self.assertRaises(self.controller.Hold): self.controller.verify_push_pack(self.root, self.previous, commit, tag)

    def test_extra_staged_path_is_rejected(self):
        self.git('add', '-A', '--', *self.allowed)
        (self.root/'unapproved').write_text('unapproved'); self.git('add', 'unapproved')
        with self.assertRaises(self.controller.Hold): self.verify()

    def test_commit_hook_tampering_fails_tree_verification(self):
        self.git('add', '-A', '--', *self.allowed)
        tree = self.git('write-tree').strip()
        blobs = self.controller.verify_staged_publication(self.root, self.snapshot, self.attested,
                                                          {self.support:b'approved evidence'}, self.allowed)
        hook = self.root/'.git'/'hooks'/'pre-commit'
        hook.write_text('#!/bin/sh\nprintf bad > unapproved\ngit add unapproved\n')
        hook.chmod(0o755)
        self.git('commit', '-qm', 'hook tampered')
        commit = self.git('rev-parse', 'HEAD').strip()
        with self.assertRaises(self.controller.Hold):
            self.controller.verify_commit_objects(self.root, commit, tree, self.previous, blobs, self.allowed)

    def test_changed_branch_or_tag_ref_holds(self):
        self.git('add', '-A', '--', *self.allowed); self.verify()
        tree = self.git('write-tree').strip()
        blobs = self.controller.verify_staged_publication(self.root, self.snapshot, self.attested,
                                                          {self.support:b'approved evidence'}, self.allowed)
        self.git('-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'snapshot')
        commit = self.git('rev-parse', 'HEAD').strip()
        self.controller.verify_commit_objects(self.root, commit, tree, self.previous, blobs, self.allowed)
        self.git('tag', '-a', 'service/1.2.3.4', '-m', 'evidence')
        tag = self.git('rev-parse', 'refs/tags/service/1.2.3.4').strip()
        branch = self.git('branch', '--show-current').strip()
        self.controller.verify_publication_refs(self.root, branch, commit, 'service/1.2.3.4', tag)
        self.git('tag', '-f', 'service/1.2.3.4', self.previous)
        with self.assertRaises(self.controller.Hold):
            self.controller.verify_publication_refs(self.root, branch, commit, 'service/1.2.3.4', tag)
        self.git('reset', '--hard', self.previous)
        with self.assertRaises(self.controller.Hold):
            self.controller.verify_publication_refs(self.root, branch, commit, 'service/1.2.3.4', tag)

class MetadataSummarySafetyTests(unittest.TestCase):
    def test_unknown_family_malformed_http_and_symlink_hold(self):
        spec=importlib.util.spec_from_file_location('metadata_safety',CLI);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'capture.json'
            for family, code in [('secret/path', 403), ('entity-metadata', '403'), ('entity-metadata', True)]:
                path.write_text(json.dumps({'evidenceKind':'contained-component-evidence-v1','status':'partial', 'versionMatchesDiscovery':True,'sources':[{'family':family,'status':'failed','failure':{'httpStatus':code}}]}))
                with self.assertRaises(m.Hold) as e:m.metadata_capture_summary(root)
                self.assertNotIn('secret',str(e.exception))
            path.unlink();path.symlink_to('/etc/passwd')
            with self.assertRaises(m.Hold):m.metadata_capture_summary(root)

    def test_only_fixed_transport_categories_are_disclosed(self):
        spec=importlib.util.spec_from_file_location('metadata_transport',CLI);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            categories=['transient-transport-exhausted','nonretryable-transport','private-host/token',{'secret':'path'}]
            rows=[{'family':'entity-metadata','status':'failed','failure':{'httpStatus':None,'category':value}} for value in categories]
            (root/'capture.json').write_text(json.dumps({'evidenceKind':'contained-component-evidence-v1','status':'partial','versionMatchesDiscovery':True,'sources':rows}))
            summary=m.metadata_capture_summary(root)
            self.assertEqual([x['reasonCategory'] for x in summary['failedSources']],['transient-transport-exhausted','nonretryable-transport','unclassified','unclassified'])
            self.assertNotIn('private-host',json.dumps(summary));self.assertNotIn('secret',json.dumps(summary))

    def test_failure_list_is_bounded_and_identity_reason_classified(self):
        spec=importlib.util.spec_from_file_location('metadata_bounds',CLI);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); rows=[{'family':'entity-metadata','status':'failed','reason':'Entity metadata did not match requested entity'} for _ in range(25)]
            (root/'capture.json').write_text(json.dumps({'evidenceKind':'contained-component-evidence-v1','status':'partial','versionMatchesDiscovery':False,'sources':rows}))
            summary=m.metadata_capture_summary(root)
            self.assertEqual(len(summary['failedSources']),20);self.assertEqual(summary['omittedFailures'],5)
            self.assertEqual(summary['failedSources'][0]['reasonCategory'],'identity-mismatch')
