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
        self.git(self.producer, 'add', '.'); self.git(self.producer, 'commit', '-m', 'synthetic producer')
        self.producer_sha = self.git(self.producer, 'rev-parse', 'HEAD').stdout.strip()
        policy={'policyVersion': 1, 'portableFamilies': ['family']}
        self.policy_sha=hashlib.sha256((json.dumps(policy,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
        self.config=self.root/'config.json';self.config.write_text(json.dumps({'schemaVersion':1,'producerRepository':'AdamCoulterOz/PowerSpec','producerCommit':self.producer_sha,'profile':'synthetic','approvedPolicySha256':self.policy_sha, **policy}))
        self.work=self.root/'private';self.work.mkdir()
        bindir=self.root/'bin';bindir.mkdir();az=bindir/'az';az.write_text("#!/bin/sh\nprintf called >> \"$TEST_AZ_CALLS\"\nprintf '%s' '{\"accessToken\":\"synthetic\"}'\n");az.chmod(0o755)
        self.env=dict(os.environ,PATH=str(bindir)+os.pathsep+os.environ.get('PATH',''),PYTHONPATH=str(ROOT/'fixtures'),SENTINEL_URL='https://synthetic.crm.dynamics.com',TEST_SENTINEL_CALLS=str(self.root/'sentinel-calls'),TEST_SENTINEL_VERSIONS='1.2.3.4',TEST_VERSION='1.2.3.4',TEST_PROFILE='synthetic',TEST_PRODUCER_SHA=self.producer_sha,TEST_POLICY_HASH=self.policy_sha,TEST_AZ_CALLS=str(self.root/'az-calls'),TEST_ACTIONS=str(self.root/'actions'))

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
        self.assertEqual((self.root/'actions').read_text().splitlines(), ['capture','normalize'])
        self.assertNotIn('SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD', result.stdout + result.stderr)
        files = self.git(self.repo,'ls-files').stdout
        self.assertNotIn('raw-private.txt', files)
        search=subprocess.run(['git','grep','-l','SYNTHETIC_PRIVATE_CAPTURE_PAYLOAD','HEAD'],cwd=self.repo,capture_output=True,text=True)
        self.assertEqual(search.returncode,1)
        result=self.run_cli();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.git(self.repo,'rev-parse','HEAD').stdout,head)
    def test_unqualified_cases_hold_without_publication(self):
        for mode in ('capture-partial','no-attestation','attestation','hash','escape','symlink'):
            with self.subTest(mode=mode):
                self.env['TEST_MODE']=mode
                result=self.run_cli();self.assertEqual(result.returncode,2,result.stdout+result.stderr)
                self.assertEqual(self.tags(),'')
                self.assertNotIn('synthetic',result.stdout+result.stderr)
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


if __name__ == '__main__':
    unittest.main()
