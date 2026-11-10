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

    def test_deployed_coverage_extra_diagnostics_and_malformed_coverage_preserve_stages(self):
        self.write_report([{'name':'coverage','status':'partial','exitCode':2}])
        (self.root/'coverage').mkdir(); path=self.root/'coverage'/'coverage.json'
        gates={name:False for name in self.controller.REQUIRED_GATES}
        report={'schemaVersion':2,'kind':'baseline-coverage-v2','profile':'private','organizationVersion':'private',
                'types':[],'requiredGateResults':gates,'diagnostics':{'dependencyOnlyAcquisition':'private',
                'scopeUnresolvedMembershipRows':4,'referenceClosure':'private','importReadiness':'private',
                'producerPublicProjectionQualified':False,'formReferenceAccounting':{'secret':'private-path'}},
                'summary':{},'complete':False,'interpretation':'private'}
        path.write_text(json.dumps(report))
        result=self.controller.acquisition_failure_summary(self.root)
        self.assertEqual(result['requiredGateResults'],gates);self.assertEqual(result['counts'],{'scopeUnresolvedMembershipRows':4})
        self.assertNotIn('private',json.dumps(result))
        for raw in ('{bad',json.dumps({**report,'unknown':'secret'})):
            path.write_text(raw);result=self.controller.acquisition_failure_summary(self.root)
            self.assertEqual(result,{'status':'incomplete','stages':[{'stage':'coverage','status':'partial','exitCode':2}],'coverageStatus':'unavailable'})

    def test_progress_polls_atomic_reports_and_suppresses_child_output(self):
        import contextlib,io
        report={'schemaVersion':1,'kind':'private-baseline-acquisition-v1','profile':'secret',
                'inputSha256':{},'stages':[{'name':'discovery','status':'complete','exitCode':0}]}
        child=("import json,os,sys,time; p=sys.argv[1]; r=json.loads(sys.argv[2]); "
               "open(p+'.tmp','w').write(json.dumps(r)); os.replace(p+'.tmp',p); "
               "print('SECRET_CHILD_OUTPUT',flush=True); time.sleep(.12); "
               "r['stages'].append({'name':'coverage','status':'failed','exitCode':1}); "
               "open(p+'.tmp','w').write(json.dumps(r));os.replace(p+'.tmp',p);sys.exit(2)")
        output=io.StringIO()
        with patch.object(self.controller,'ACQUISITION_PROGRESS_INTERVAL',.02),contextlib.redirect_stdout(output):
            code=self.controller.execute_acquisition([sys.executable,'-c',child,str(self.root/'acquisition.json'),json.dumps(report)],self.root)
        self.assertEqual(code,2)
        text=output.getvalue();self.assertEqual(text.count('"stage":"discovery"'),1);self.assertEqual(text.count('"stage":"coverage"'),1)
        self.assertNotIn('SECRET',text);self.assertNotIn('secret',text)

    def test_interruption_stops_producer_and_term_ignoring_descendant(self):
        import fcntl,time
        lock=self.root/'descendant.lock'; ready=self.root/'ready'; parent_pid=self.root/'parent.pid'
        grandchild=("import fcntl,signal,sys,time; f=open(sys.argv[1],'w'); "
                    "fcntl.flock(f,fcntl.LOCK_EX); signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                    "open(sys.argv[2],'w').write('ready'); time.sleep(60)")
        parent=("import os,subprocess,sys,time; open(sys.argv[3],'w').write(str(os.getpid())); "
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[4]]); time.sleep(60)")
        def interrupt_when_ready(*args,**kwargs):
            if ready.exists(): raise KeyboardInterrupt()
            return {'status':'unavailable'}
        with patch.object(self.controller,'ACQUISITION_PROGRESS_INTERVAL',.05), patch.object(self.controller,'acquisition_failure_summary',side_effect=interrupt_when_ready):
            with self.assertRaises(KeyboardInterrupt):
                self.controller.execute_acquisition([sys.executable,'-c',parent,grandchild,str(lock),str(parent_pid),str(ready)],self.root)
        self.assertTrue(ready.exists());self.assertTrue(parent_pid.exists())
        with self.assertRaises(ProcessLookupError): os.kill(int(parent_pid.read_text()),0)
        with lock.open('w') as stream:
            deadline=time.monotonic()+3
            while True:
                try:
                    fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:self.fail('Descendant survived interruption')
                    time.sleep(.02)

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

class AcquisitionEvidenceSummaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        spec=importlib.util.spec_from_file_location('evidence_summary',CLI); self.controller=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.controller)
    def write(self,name,value):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value))
    def test_scoped_counts_and_allowlisted_projection_only(self):
        scope={'schemaVersion':1,'kind':'solution-membership-scope-v1','entries':[{'componentType':2,'disposition':'unresolved','objectId':'SECRET'}, {'componentType':2,'disposition':'unresolved'}, {'componentType':9,'disposition':'required'}]}
        self.write('scope-preflight/scope-ledger.json',scope);self.write('projection/scope-ledger.json',scope)
        self.write('nonmaterialization/nonmaterialization.json',{'schemaVersion':1,'kind':'membership-nonmaterialization-v1','observations':[{'componentType':2,'qualified':True,'evidence':'SECRET'}, {'componentType':2,'qualified':False}]})
        projection={'schemaVersion':1,'kind':'private-public-projection-candidate-v1', 'sourceVerified':True,'sourceComplete':False,'contentComplete':False,'fieldPolicyComplete':False,'lossAccountingComplete':True,'reproducible':True,'uniqueUnclassifiedFieldCount':3,'unclassifiedFields':[{'field':'SECRET'}], 'diagnosticCounts':{'scope-unresolved-membership':2,'secret-path':99}}
        self.write('projection/projection.json',projection)
        r=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(r['preliminaryScope'],[{'componentType':2,'category':'unresolved','count':2}]);self.assertEqual(r['finalScope'],r['preliminaryScope'])
        self.assertEqual(r['nonmaterialization'],[{'componentType':2,'category':'qualified','count':1},{'componentType':2,'category':'unqualified','count':1}])
        self.assertEqual(r['projection']['diagnosticCounts'],{'scope-unresolved-membership':2});self.assertEqual(r['projection']['unclassifiedFieldCount'],3)
        self.assertNotIn('SECRET',json.dumps(r));self.assertNotIn('secret-path',json.dumps(r))
        projection['reproducible']=None;self.write('projection/projection.json',projection)
        self.assertNotIn('reproducible',self.controller.acquisition_evidence_summary(self.root)['projection']['gates'])
    def test_bad_optional_report_does_not_suppress_other_evidence(self):
        self.write('scope-preflight/scope-ledger.json',{'schemaVersion':1,'kind':'solution-membership-scope-v1','entries':[{'componentType':'PRIVATE','disposition':'unresolved'}]})
        self.write('nonmaterialization/nonmaterialization.json',{'schemaVersion':1,'kind':'membership-nonmaterialization-v1','observations':[{'componentType':1,'qualified':False}]})
        r=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(r['preliminaryScope'],{'status':'unavailable'});self.assertEqual(r['nonmaterialization'][0]['count'],1)
        self.assertNotIn('PRIVATE',json.dumps(r))

class TerminalTelemetrySafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        spec=importlib.util.spec_from_file_location('terminal_telemetry',CLI);self.controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.controller)
    def write(self,name,value):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value))
    def bind(self,stage,path):
        report_path=self.root/'acquisition.json'
        report=json.loads(report_path.read_text()) if report_path.exists() else {'schemaVersion':1,'kind':'private-baseline-acquisition-v1','stages':[]}
        report['stages'].append({'name':stage,'status':'partial','exitCode':2,'reportSha256':hashlib.sha256((self.root/path).read_bytes()).hexdigest()})
        report_path.write_text(json.dumps(report))
    def test_nonmaterialization_aggregates_fixed_facts_without_private_details(self):
        self.write('nonmaterialization/nonmaterialization.json',{'schemaVersion':1,'kind':'membership-nonmaterialization-v1',
            'callerMatches':True,'versionBracketMatches':False,'controls':{'1':{'matched':True,'enumerationMatchesDiscovery':False,'objectId':'SECRET'},'2':{'matched':False}},
            'responses':{'privileges':{'httpStatus':403,'requestPath':'SECRET'}},
            'observations':[{'componentType':1,'qualified':False,'disposition':'access-denied','objectId':'SECRET'},
                            {'componentType':2,'qualified':False,'disposition':'SECRET'}]})
        self.bind('nonmaterialization','nonmaterialization/nonmaterialization.json')
        result=self.controller.acquisition_evidence_summary(self.root)['nonmaterializationDetail']
        self.assertEqual(result['privilegeResponse'],'forbidden');self.assertEqual(result['controls']['1'],True)
        self.assertFalse(result['controls']['1EnumerationMatchesDiscovery']);self.assertFalse(result['versionBracketMatches'])
        self.assertEqual(result['observations'][0]['disposition'],'access-denied');self.assertEqual(result['observations'][1]['disposition'],'other')
        self.assertNotIn('SECRET',json.dumps(result))
    def test_operational_allowlists_and_malformed_are_isolated(self):
        self.write('operational-scope/manifest.json',{'schemaVersion':1,'kind':'private-operational-scope-capture-v1','result':{
            'complete':False,'candidates':[{'componentType':20,'ruleId':'verified-instrumentation-role-v1','objectId':'SECRET'}],
            'unresolved':[{'componentType':92,'reason':'creator-unresolved','objectId':'SECRET'}, {'componentType':65000,'reason':'SECRET'}],
            'requiredLookupScanUnresolvedCount':3,'requiredLookupScanReasons':{'lookup-not-readable':2,'SECRET':1}}})
        self.write('nonmaterialization/nonmaterialization.json',{'schemaVersion':1,'kind':'membership-nonmaterialization-v1','observations':[{'componentType':1,'qualified':False}]})
        self.bind('operational-scope','operational-scope/manifest.json')
        result=self.controller.acquisition_evidence_summary(self.root)
        detail=result['operationalScope'];self.assertEqual(detail['candidates'][0]['componentType'],20)
        self.assertEqual(detail['requiredLookupScanReasons'],{'lookup-not-readable':2,'other':1})
        self.assertNotIn('SECRET',json.dumps(result))
        p=self.root/'operational-scope'/'manifest.json';value=json.loads(p.read_text());value['result']['requiredLookupScanUnresolvedCount']=4;p.write_text(json.dumps(value))
        result=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(result['operationalScope'],{'status':'unavailable'});self.assertEqual(result['nonmaterialization'][0]['count'],1)

    def test_invalid_acquisition_authority_and_changed_bytes_do_not_hide_other_summary(self):
        path='nonmaterialization/nonmaterialization.json'
        data={'schemaVersion':1,'kind':'membership-nonmaterialization-v1','observations':[{'componentType':1,'qualified':False,'disposition':'request-failed'}]}
        self.write(path,data);self.bind('nonmaterialization',path)
        report_path=self.root/'acquisition.json';report=json.loads(report_path.read_text())
        for bad in ({'stages':report['stages']},{**report,'schemaVersion':True},{**report,'kind':'SECRET'}, {**report,'stages':[{**report['stages'][0],'exitCode':0}]}):
            with self.subTest(authority=bad):
                report_path.write_text(json.dumps(bad));result=self.controller.acquisition_evidence_summary(self.root)
                self.assertEqual(result['nonmaterializationDetail'],{'status':'unavailable'});self.assertEqual(result['nonmaterialization'][0]['count'],1)
                self.assertNotIn('SECRET',json.dumps(result))
        report_path.write_text(json.dumps(report));data['observations'].append({'componentType':1,'qualified':False,'disposition':'request-failed'});self.write(path,data)
        result=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(result['nonmaterializationDetail'],{'status':'unavailable'});self.assertEqual(result['nonmaterialization'][0]['count'],2)

    @unittest.skipUnless(hasattr(os, 'mkfifo') and hasattr(os, 'O_NONBLOCK'), 'POSIX FIFO support required')
    def test_fifo_evidence_is_rejected_without_blocking(self):
        path=self.root/'fifo';os.mkfifo(path)
        child=("import importlib.util,sys; s=importlib.util.spec_from_file_location('pipeline',sys.argv[1]); "
               "m=importlib.util.module_from_spec(s);s.loader.exec_module(m); "
               "\ntry: m._bounded_safe_bytes(sys.argv[2],'fifo')\nexcept m.Hold: sys.exit(0)\nsys.exit(1)")
        result=subprocess.run([sys.executable,'-c',child,str(CLI),str(self.root)],capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_atomic_replacement_after_read_never_summarizes_unbound_bytes(self):
        path='operational-scope/manifest.json'
        data={'schemaVersion':1,'kind':'private-operational-scope-capture-v1','result':{'complete':False,'candidates':[],
              'unresolved':[],'requiredLookupScanUnresolvedCount':1,'requiredLookupScanReasons':{'lookup-not-readable':1}}}
        self.write(path,data);self.bind('operational-scope',path)
        original=self.controller._bounded_safe_bytes;calls=[]
        def replace_after_read(root,relative,*args,**kwargs):
            raw=original(root,relative,*args,**kwargs)
            if relative==path:
                calls.append(relative);data['result']['requiredLookupScanUnresolvedCount']=2;data['result']['requiredLookupScanReasons']['lookup-not-readable']=2
                replacement=self.root/'operational-scope'/'new.tmp';replacement.write_text(json.dumps(data));os.replace(replacement,self.root/path)
            return raw
        with patch.object(self.controller,'_bounded_safe_bytes',side_effect=replace_after_read):
            result=self.controller.acquisition_evidence_summary(self.root)['operationalScope']
        self.assertEqual(calls,[path]);self.assertEqual(result['requiredLookupScanUnresolvedCount'],1)
        self.assertEqual(json.loads((self.root/path).read_text())['result']['requiredLookupScanUnresolvedCount'],2)

    def test_projection_issue_groups_are_hash_bound_and_fixed(self):
        path='projection/projection.json'
        groups={'required-identity-unresolved':[{'componentType':1,'category':'missing-unit','count':2}],
                'required-representation-missing':[],'typed-reference-unresolved':[{'componentType':60,'category':'workflow-form','count':1}],
                'unclassified-field':[]}
        data={'schemaVersion':1,'kind':'private-public-projection-candidate-v1','sourceVerified':True,'sourceComplete':False,
              'contentComplete':False,'fieldPolicyComplete':False,'lossAccountingComplete':True,'reproducible':True,
              'uniqueUnclassifiedFieldCount':0,'diagnosticCounts':{'required-identity-unresolved':2,'typed-reference-unresolved':1},
              'issueDiagnostics':{'schemaVersion':1,'groups':groups},'secret':'PRIVATE'}
        self.write(path,data);self.bind('projection-replay',path)
        result=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(result['projectionIssueDiagnostics']['groups'],groups)
        self.assertNotIn('PRIVATE',json.dumps(result))
        data['issueDiagnostics']['groups']['required-identity-unresolved'][0]['count']=3
        self.write(path,data)
        result=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(result['projectionIssueDiagnostics'],{'status':'unavailable'});self.assertEqual(result['projection']['gates']['sourceComplete'],False)

    def test_invalid_bound_projection_issue_buckets_remain_optional(self):
        import copy
        path='projection/projection.json'
        groups={'required-identity-unresolved':[{'componentType':1,'category':'missing-unit','count':1}],
                'required-representation-missing':[],'typed-reference-unresolved':[],'unclassified-field':[]}
        base={'schemaVersion':1,'kind':'private-public-projection-candidate-v1','sourceVerified':True,'sourceComplete':False,
              'contentComplete':False,'fieldPolicyComplete':False,'lossAccountingComplete':True,'reproducible':True,
              'uniqueUnclassifiedFieldCount':0,'diagnosticCounts':{'required-identity-unresolved':1},'issueDiagnostics':{'schemaVersion':1,'groups':groups}}
        bad=[]
        x=copy.deepcopy(base);x['issueDiagnostics']['groups']['required-identity-unresolved'][0]['category']='PRIVATE';bad.append(x)
        x=copy.deepcopy(base);x['issueDiagnostics']['groups']['required-identity-unresolved'][0]['componentType']=True;bad.append(x)
        x=copy.deepcopy(base);x['issueDiagnostics']['groups']['required-identity-unresolved'].append(dict(x['issueDiagnostics']['groups']['required-identity-unresolved'][0]));bad.append(x)
        x=copy.deepcopy(base);x['issueDiagnostics']['groups']['required-identity-unresolved'][0]['count']=2;bad.append(x)
        x=copy.deepcopy(base);x['issueDiagnostics']['groups']['PRIVATE']=[];bad.append(x)
        for data in bad:
            with self.subTest(data=data):
                self.write(path,data);(self.root/'acquisition.json').unlink(missing_ok=True);self.bind('projection-replay',path)
                result=self.controller.acquisition_evidence_summary(self.root)
                self.assertEqual(result['projectionIssueDiagnostics'],{'status':'unavailable'});self.assertFalse(result['projection']['gates']['sourceComplete'])
                self.assertNotIn('PRIVATE',json.dumps(result))

class LegacyProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        spec=importlib.util.spec_from_file_location('legacy_probe_controller',CLI);self.controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.controller)
    def manifest(self):
        return {'schemaVersion':1,'kind':'legacy-component-private-capture-v1','status':'partial','selectionScope':'selected-types','privateComplete':False,
                'discoveryVersion':'1.2.3.4','versionBefore':'1.2.3.4','versionAfter':'1.2.3.4','versionBracketMatches':True,
                'solutionsBeforeMatchesDiscovery':True,'solutionsBracketMatches':True,
                'types':[{'componentType':n,'status':'captured','selectedCount':1,'invalidSelectionCount':0,'objects':[{'status':'captured','objectId':'SECRET'}]} for n in (62,80)],
                'sources':[{'componentType':n,'status':'complete','attemptKind':'initial','batchIndex':0,'requestPath':'SECRET'} for n in (62,80)]}
    def test_selected_partial_status_can_qualify_only_with_both_types_and_brackets(self):
        data=self.manifest();summary=self.controller.legacy_manifest_summary(data,expected_version='1.2.3.4')
        self.assertTrue(self.controller.legacy_probe_complete(summary));self.assertEqual(summary['sourceCounts'][0]['httpCategory'],'unavailable');self.assertEqual(summary['callerBracket'],'not-recorded');self.assertNotIn('SECRET',json.dumps(summary))
        for change in ('failure','missing','version','solutions','partial','scope','privateComplete','extra','sentinel'):
            import copy
            value=copy.deepcopy(data)
            if change=='failure':value['status']='failed'
            if change=='missing':value['types'].pop()
            if change=='version':value['versionBracketMatches']=False;value['versionAfter']='1.2.3.5'
            if change=='solutions':value.pop('solutionsBracketMatches')
            if change=='partial':value['types'][0]['status']='partial'
            if change=='scope':value['selectionScope']='all-non-definition-in-use'
            if change=='privateComplete':value['privateComplete']=True
            if change=='extra':value['types'].append({'componentType':99})
            self.assertFalse(self.controller.legacy_probe_complete(self.controller.legacy_manifest_summary(value,expected_version='9.9.9.9' if change=='sentinel' else '1.2.3.4')))
    def test_terminal_legacy_requires_matching_stage_hash_and_preserves_other_summary(self):
        directory=self.root/'legacy';directory.mkdir();path=directory/'manifest.json';path.write_text(json.dumps(self.manifest()))
        report={'schemaVersion':1,'kind':'private-baseline-acquisition-v1','stages':[{'name':'legacy-capture','status':'failed','exitCode':1,'reportSha256':hashlib.sha256(path.read_bytes()).hexdigest()}]}
        (self.root/'acquisition.json').write_text(json.dumps(report));summary=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(summary['legacyCapture']['status'],'partial');self.assertNotIn('SECRET',json.dumps(summary))
        path.write_text(json.dumps({**self.manifest(),'status':'failed'}));summary=self.controller.acquisition_evidence_summary(self.root)
        self.assertEqual(summary['legacyCapture'],{'status':'unavailable'})
        report['stages'][0]['status']='blocked';(self.root/'acquisition.json').write_text(json.dumps(report))
        self.assertEqual(self.controller.acquisition_evidence_summary(self.root)['legacyCapture'],{'status':'unavailable'})
    def test_manual_mode_uses_exact_two_type_command_and_no_publication(self):
        import contextlib,io
        module=self.controller;producer=self.root/'producer';producer.mkdir();work=self.root/'work';work.mkdir();pin='a'*40;calls=[]
        class Result:
            def __init__(self,stdout='',returncode=0):self.stdout=stdout;self.returncode=returncode
        def fake_execute(args,**kwargs):
            calls.append(args)
            if args[:2]==['git','status']:return Result()
            if args[:2]==['git','branch']:return Result('main')
            if args[:2]==['git','rev-parse']:return Result(pin)
            if 'discover' in args:
                Path(args[args.index('--output')+1]).mkdir();return Result()
            if any(str(x).endswith('legacy_capture.py') for x in args):
                out=Path(args[args.index('--output')+1]);out.mkdir();(out/'manifest.json').write_text(json.dumps(self.manifest()));return Result(returncode=2)
            raise AssertionError('Unexpected command')
        argv=[str(CLI),'--config','unused','--workdir',str(work),'--producer',str(producer),'--mode','legacy-probe']
        env={'SENTINEL_URL':'https://example.invalid','POWERSPEC_AUTH_MODE':'github-oidc'};output=io.StringIO()
        with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',argv),patch.object(module,'config',return_value={'producerCommit':pin,'profile':'synthetic'}),patch.object(module,'execute',side_effect=fake_execute),patch.object(module,'sentinel',return_value='1.2.3.4'),patch.object(module,'oidc_identity_check') as identity,patch.object(module,'existing_tag',side_effect=AssertionError('Unexpected tag')),contextlib.redirect_stdout(output):
            self.assertEqual(module.main(),0)
        capture=next(x for x in calls if any(str(v).endswith('legacy_capture.py') for v in x))
        self.assertEqual([capture[i+1] for i,x in enumerate(capture) if x=='--only-type'],['62','80'])
        self.assertEqual(identity.call_count,2);self.assertIn('application identity matched before and after',output.getvalue());self.assertNotIn('SECRET',output.getvalue())
        self.assertFalse(any(x[:2]==['git','push'] for x in calls))

    def test_fixed_failure_class_and_http_categories_never_copy_raw_text(self):
        data=self.manifest();data.update(status='failed',failureClass='PRIVATE_EXCEPTION')
        data['sources']=[{'componentType':80,'status':'failed','attemptKind':'initial','batchIndex':0,'httpStatus':500,'failureClass':'PRIVATE_EXCEPTION','reason':'PRIVATE_PATH'}]
        summary=self.controller.legacy_manifest_summary(data)
        self.assertEqual(summary['failureClass'],'other');self.assertEqual(summary['sourceCounts'][0]['failureClass'],'other')
        self.assertEqual(summary['sourceCounts'][0]['httpCategory'],'server-error');self.assertNotIn('PRIVATE',json.dumps(summary))
        data['sources'][0]['httpStatus']='PRIVATE';
        with self.assertRaises(ValueError):self.controller.legacy_manifest_summary(data)

    def test_probe_requires_complete_sources_and_only_supported_recovery(self):
        import copy
        data=self.manifest();data['sources'].pop()
        self.assertFalse(self.controller.legacy_probe_complete(self.controller.legacy_manifest_summary(data,expected_version='1.2.3.4')))
        base=self.manifest();failed={'componentType':62,'status':'failed','attemptKind':'initial','batchIndex':8,'failureClass':'HTTPError','httpStatus':500,'failureKind':'request-failed','recoveryStatus':'recovered'}
        retry={'componentType':62,'status':'complete','attemptKind':'single-retry','batchIndex':8,'parentBatchIndex':8,'requestedCount':1}
        data=copy.deepcopy(base);data['sources'].extend([failed,retry])
        self.assertTrue(self.controller.legacy_probe_complete(self.controller.legacy_manifest_summary(data,expected_version='1.2.3.4')))
        for http in (401,403,404,429):
            with self.subTest(http=http):
                value=copy.deepcopy(data);value['sources'][-2]['httpStatus']=http
                self.assertFalse(self.controller.legacy_probe_complete(self.controller.legacy_manifest_summary(value,expected_version='1.2.3.4')))
        for kind in ('missing-retry','invalid','unrecovered'):
            with self.subTest(kind=kind):
                value=copy.deepcopy(data)
                if kind=='missing-retry':value['sources'].pop()
                if kind=='invalid':value['sources'][-1]['status']='invalid-response'
                if kind=='unrecovered':value['sources'][-2]['recoveryStatus']='unrecovered'
                self.assertFalse(self.controller.legacy_probe_complete(self.controller.legacy_manifest_summary(value,expected_version='1.2.3.4')))
