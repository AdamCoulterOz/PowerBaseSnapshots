#!/usr/bin/env python3
"""Read-only sentinel capture and fail-closed, attested publication coordinator."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

# GitHub's published Ed25519 host key: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
GITHUB_HOST_KEY = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n'

VERSION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
SHA = re.compile(r'^[0-9a-f]{40}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
PROFILE = re.compile(r'^[a-z0-9][a-z0-9-]{0,63}$')

class Hold(Exception): pass


def execute(args, cwd=None, env=None, allowed=(0,)):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode not in allowed:
        raise Hold('An external command failed; sensitive command output was withheld.')
    return result


def load(path):
    def reject_constant(value):
        raise ValueError('Nonfinite JSON number')
    return json.loads(Path(path).read_text(encoding='utf-8'), parse_constant=reject_constant)


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value): raise Hold('Sentinel version is not a numeric four-part version.')
    return value


def sentinel(origin):
    url = urllib.parse.urlsplit(origin)
    if (url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.dynamics.com')
            or url.netloc.lower() != url.hostname.lower() or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/')):
        raise Hold('Invalid sentinel origin.')
    base = 'https://' + url.netloc
    token_data = execute(['az', 'account', 'get-access-token', '--resource', base, '--output', 'json'])
    token = json.loads(token_data.stdout).get('accessToken')
    if not isinstance(token, str) or not token: raise Hold('Azure token unavailable.')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): raise Hold('Sentinel redirect rejected.')
    request = urllib.request.Request(base + '/api/data/v9.2/RetrieveVersion()', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            return version(json.load(response).get('Version'))
    except (OSError, ValueError, urllib.error.HTTPError):
        raise Hold('Sentinel version request failed.') from None


def config(path):
    c = load(path)
    if c.get('schemaVersion') != 1 or c.get('producerRepository') != 'AdamCoulterOz/PowerSpec' or not PROFILE.fullmatch(c.get('profile', '')):
        raise Hold('Invalid pipeline configuration.')
    return c


def qualify(c):
    if not SHA.fullmatch(c.get('producerCommit') or '') or not SHA256.fullmatch(c.get('approvedPolicySha256') or '') or not c.get('portableFamilies'):
        raise Hold('Producer revision and approved portable publication policy are not configured.')
    policy = {k:c[k] for k in ('policyVersion', 'portableFamilies')}
    if hashlib.sha256(canonical(policy)).hexdigest() != c['approvedPolicySha256']:
        raise Hold('Approved policy hash does not match the configured policy.')
    if not isinstance(c['portableFamilies'], list) or len(set(c['portableFamilies'])) != len(c['portableFamilies']) or not all(isinstance(f, str) and f for f in c['portableFamilies']):
        raise Hold('Invalid portable family policy.')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()


def tree_hash(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): raise Hold('Unsafe snapshot root.')
    files = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink(): raise Hold('Snapshot contains a symlink.')
        if path.is_dir(): continue
        if not path.is_file(): raise Hold('Snapshot contains a nonregular file.')
        rel = path.relative_to(root).as_posix()
        if any(x in ('', '.', '..') for x in PurePosixPath(rel).parts): raise Hold('Unsafe snapshot path.')
        files.append({'path': rel, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size})
    return hashlib.sha256(canonical(files)).hexdigest(), files


def verify_capture(root, c, v):
    root = Path(root)
    manifest = load(root / 'capture.json')
    if (manifest.get('schemaVersion') != 1 or manifest.get('profile') != c['profile']
            or manifest.get('status') != 'complete' or manifest.get('fullConfigurationComplete') is not True
            or manifest.get('organizationVersion') != v):
        raise Hold('Capture profile, completeness or version is invalid.')
    consistency = manifest.get('inventoryConsistency', {})
    if consistency.get('solutionsMatch') is not True or consistency.get('organizationVersionMatch') is not True:
        raise Hold('Capture consistency check failed.')
    sources = manifest.get('sources')
    if not isinstance(sources, list): raise Hold('Capture source evidence is missing.')
    for source_name in ('organization-version-before', 'organization-version-after'):
        matching = [item for item in sources if item.get('name') == source_name]
        if len(matching) != 1 or matching[0].get('status') != 'complete' or len(matching[0].get('pages', [])) != 1:
            raise Hold('Capture version evidence is incomplete.')
        page = matching[0]['pages'][0]; relative = page.get('path')
        if not isinstance(relative, str) or '\\' in relative:
            raise Hold('Unsafe capture version evidence path.')
        parts = PurePosixPath(relative).parts
        if not parts or PurePosixPath(relative).is_absolute() or any(p in ('', '.', '..') for p in parts):
            raise Hold('Unsafe capture version evidence path.')
        path = root
        for part in parts:
            path = path / part
            if path.is_symlink(): raise Hold('Capture version evidence symlink rejected.')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != page.get('sha256') or json.loads(data).get('Version') != v:
            raise Hold('Capture version evidence does not match sentinel.')

def verify_snapshot(root, c, v, attestation):
    root = Path(root)
    manifest, coverage = load(root/'manifest.json'), load(root/'coverage.json')
    if manifest.get('schemaVersion') != 1 or manifest.get('profile') != c['profile'] or manifest.get('organizationVersion') != v:
        raise Hold('Snapshot profile or version mismatch.')
    if manifest.get('complete') is not True or coverage.get('complete') is not True:
        raise Hold('Snapshot coverage is incomplete.')
    if not coverage.get('componentTypes') or any(item.get('complete') is not True for item in coverage['componentTypes']):
        raise Hold('One or more component families are incomplete.')
    if not coverage.get('sources') or any(source.get('status') != 'complete' for source in coverage['sources']):
        raise Hold('One or more captured sources are incomplete.')
    consistency = coverage.get('inventoryConsistency', {})
    if consistency.get('solutionsMatch') is not True or consistency.get('organizationVersionMatch') is not True or coverage.get('scopeTruncated') is not False:
        raise Hold('Snapshot consistency or scope check failed.')
    seen = set()
    for doc in manifest.get('documents', []):
        rel = doc.get('path'); family = doc.get('family')
        if family not in c['portableFamilies'] or not isinstance(rel, str) or '\\' in rel: raise Hold('Document family or path is not approved.')
        parts = PurePosixPath(rel).parts
        if not parts or PurePosixPath(rel).is_absolute() or any(p in ('', '.', '..') for p in parts) or rel.casefold() in seen: raise Hold('Unsafe or duplicate document path.')
        seen.add(rel.casefold()); path = root
        for part in parts:
            path = path / part
            if path.is_symlink(): raise Hold('Document symlink rejected.')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != doc.get('sha256'): raise Hold('Document hash check failed.')
    digest, files = tree_hash(root)
    actual = {x['path'].casefold() for x in files}
    if actual != seen | {'manifest.json', 'coverage.json', 'provenance.json'}:
        raise Hold('Snapshot contains missing or unexpected files.')
    expected = {'schemaVersion': 1, 'snapshotSha256': digest, 'profile': c['profile'], 'producerCommit': c['producerCommit'],
                'policySha256': c['approvedPolicySha256'], 'sourceVersionBefore': v, 'sourceVersionAfter': v,
                'familyCoverage': 'complete', 'portability': 'qualified', 'provenance': 'qualified', 'publicSafety': 'qualified'}
    if attestation != expected: raise Hold('Publication attestation missing or does not match approved facts.')
    return digest


def existing_tag(repo, tag, c, v):
    result = execute(['git', 'ls-remote', '--refs', 'origin', 'refs/tags/' + tag], cwd=repo)
    if not result.stdout.strip(): return False
    execute(['git', 'fetch', '--no-tags', 'origin', 'refs/tags/' + tag + ':refs/tags/' + tag], cwd=repo)
    kind = execute(['git', 'cat-file', '-t', 'refs/tags/' + tag], cwd=repo).stdout.strip()
    if kind != 'tag': raise Hold('Existing service tag is not annotated.')
    raw = execute(['git', 'for-each-ref', '--format=%(contents)', 'refs/tags/' + tag], cwd=repo).stdout
    try: evidence = json.loads(raw)
    except ValueError: raise Hold('Existing service tag has no valid publication evidence.') from None
    if any(evidence.get(k) != val for k,val in {'profile':c['profile'], 'producerCommit':c['producerCommit'], 'policySha256':c['approvedPolicySha256'], 'serviceVersion':v}.items()) or not SHA256.fullmatch(evidence.get('snapshotSha256', '')):
        raise Hold('Existing service tag conflicts with current publication configuration.')
    commit = execute(['git', 'rev-list', '-n', '1', 'refs/tags/' + tag], cwd=repo).stdout.strip()
    if execute(['git', 'merge-base', '--is-ancestor', commit, 'HEAD'], cwd=repo, allowed=(0,1)).returncode != 0:
        raise Hold('Existing tag is not contained in the checked-out branch.')
    # Verify evidence is tied to the committed version manifest, not merely a tag message.
    recorded = execute(['git', 'show', f'{commit}:versions/{c["profile"]}/{v}.json'], cwd=repo).stdout
    if json.loads(recorded) != evidence: raise Hold('Existing tag and committed version evidence disagree.')
    with tempfile.TemporaryDirectory(prefix='powerspec-tag-verify-') as tmp:
        archive = Path(tmp) / 'baseline.tar'
        with archive.open('wb') as stream:
            result = subprocess.run(['git', 'archive', commit, 'baselines/' + c['profile']], cwd=repo,
                                    stdout=stream, stderr=subprocess.PIPE)
        if result.returncode != 0: raise Hold('Existing tagged baseline cannot be read.')
        try:
            with tarfile.open(archive) as tar:
                tar.extractall(Path(tmp) / 'contents', filter='data')
        except (tarfile.TarError, OSError):
            raise Hold('Existing tagged baseline is unsafe.') from None
        digest, _ = tree_hash(Path(tmp) / 'contents' / 'baselines' / c['profile'])
        if digest != evidence['snapshotSha256']: raise Hold('Existing tagged baseline content does not match evidence.')
    return True


def clone_producer(c, directory):
    key = os.environ.get('PRODUCER_SSH_KEY', '')
    if not key: raise Hold('Read-only producer deploy key is unavailable.')
    keyfile = Path(directory)/'deploy-key'; keyfile.write_text(key); keyfile.chmod(0o600)
    known_hosts = Path(directory)/'known_hosts'; known_hosts.write_text(GITHUB_HOST_KEY); known_hosts.chmod(0o600)
    env = os.environ.copy()
    env['GIT_SSH_COMMAND'] = f'ssh -i {shlex.quote(str(keyfile))} -o UserKnownHostsFile={shlex.quote(str(known_hosts))} -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes'
    target = Path(directory)/'producer'
    execute(['git', 'clone', '--no-checkout', '--filter=blob:none', 'git@github.com:AdamCoulterOz/PowerSpec.git', str(target)], env=env)
    execute(['git', 'checkout', '--detach', c['producerCommit']], cwd=target, env=env)
    if execute(['git', 'rev-parse', 'HEAD'], cwd=target).stdout.strip() != c['producerCommit']: raise Hold('Producer revision mismatch.')
    keyfile.unlink()
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='pipeline/config.json'); parser.add_argument('--workdir', required=True)
    parser.add_argument('--producer', help='Optional clean, pinned local producer checkout')
    parser.add_argument('--mode', choices=['check','run'], default='run')
    args = parser.parse_args(); repo = Path.cwd(); c = config(args.config)
    origin = os.environ.get('SENTINEL_URL', '')
    if not origin: raise Hold('Sentinel is not configured.')
    if execute(['git', 'status', '--porcelain'], cwd=repo).stdout.strip(): raise Hold('Working tree is not clean.')
    branch = execute(['git', 'branch', '--show-current'], cwd=repo).stdout.strip()
    if not branch: raise Hold('An attached publication branch is required.')
    v = sentinel(origin); tag = 'service/' + v
    print('Observed service version: ' + v)
    if existing_tag(repo, tag, c, v): print('Already published and verified.'); return 0
    if args.mode == 'check': print('New sentinel version; publication is not yet established.'); return 0
    qualify(c)
    base = Path(args.workdir).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='powerspec-private-', dir=base) as tmp:
        private = Path(tmp)
        if args.producer:
            producer = Path(args.producer).resolve(strict=True)
            if (execute(['git', 'rev-parse', 'HEAD'], cwd=producer).stdout.strip() != c['producerCommit']
                    or execute(['git', 'status', '--porcelain'], cwd=producer).stdout.strip()):
                raise Hold('Local producer does not match the clean pinned revision.')
        else:
            producer = clone_producer(c, private)
        cli = producer/'tools/PowerSpec.Baseline/baseline.py'; capture = private/'capture'; snapshot = private/'snapshot'
        status = execute([sys.executable, str(cli), 'capture', '--environment', origin, '--profile', c['profile'], '--output', str(capture)], allowed=(0,2))
        if status.returncode != 0: raise Hold('Capture incomplete; publication withheld.')
        verify_capture(capture, c, v)
        status = execute([sys.executable, str(cli), 'normalize', '--input', str(capture), '--output', str(snapshot)], allowed=(0,2))
        if status.returncode != 0: raise Hold('Normalization incomplete; publication withheld.')
        if sentinel(origin) != v: raise Hold('Sentinel version changed during capture.')
        attestation_path = private/'attestation.json'
        if not attestation_path.is_file(): raise Hold('Qualified publication attestation is unavailable.')
        digest = verify_snapshot(snapshot, c, v, load(attestation_path))
        prior = repo/'baselines'/c['profile']; delta = private/'diff'
        if prior.exists():
            status = execute([sys.executable, str(cli), 'diff', '--previous', str(prior), '--current', str(snapshot), '--output', str(delta)], allowed=(0,2))
            if status.returncode != 0: raise Hold('Previous baseline diff is incomparable.')
        # Revalidate source state and publication head immediately before modifying the worktree.
        if sentinel(origin) != v: raise Hold('Sentinel version changed before publication.')
        head = execute(['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.strip()
        remote = execute(['git', 'ls-remote', '--heads', 'origin', 'refs/heads/' + branch], cwd=repo).stdout.split()
        if not remote or remote[0] != head: raise Hold('Remote branch changed; retry with a fresh checkout.')
        if execute(['git', 'status', '--porcelain'], cwd=repo).stdout.strip(): raise Hold('Working tree changed during capture.')
        diff_target = repo/'diffs'/c['profile']/v
        version_file = repo/'versions'/c['profile']/(v+'.json')
        if diff_target.exists() or diff_target.is_symlink() or version_file.exists() or version_file.is_symlink():
            raise Hold('Version output already exists without a verified tag.')
        for parent in (repo/'baselines', repo/'diffs', repo/'versions', prior.parent, diff_target.parent, version_file.parent):
            if parent.is_symlink(): raise Hold('Publication path contains a symlink.')
        if prior.exists() and execute(['git', 'ls-files', '--others', '--ignored', '--exclude-standard', '--', str(prior.relative_to(repo))], cwd=repo).stdout.strip():
            raise Hold('Baseline contains ignored files; refusing replacement.')
        if prior.is_symlink(): raise Hold('Baseline symlink rejected.')
        if prior.exists(): shutil.rmtree(prior)
        prior.parent.mkdir(parents=True, exist_ok=True); shutil.copytree(snapshot, prior)
        if delta.exists(): diff_target.parent.mkdir(parents=True, exist_ok=True); shutil.copytree(delta, diff_target)
        evidence = {'profile':c['profile'], 'producerCommit':c['producerCommit'], 'policySha256':c['approvedPolicySha256'], 'serviceVersion':v, 'snapshotSha256':digest}
        version_file.parent.mkdir(parents=True, exist_ok=True); version_file.write_bytes(canonical(evidence))
        allowed = [str(prior.relative_to(repo)), str(version_file.relative_to(repo))]
        if delta.exists(): allowed.append(str(diff_target.relative_to(repo)))
        execute(['git', 'add', '-A', '--', *allowed], cwd=repo)
        execute(['git', '-c', 'user.name=PowerBaseSnapshots automation', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'commit', '-m', 'Capture service ' + v], cwd=repo)
        execute(['git', '-c', 'user.name=PowerBaseSnapshots automation', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com', 'tag', '-a', tag, '-m', canonical(evidence).decode()], cwd=repo)
        execute(['git', 'push', '--atomic', 'origin', 'HEAD:refs/heads/' + branch, 'refs/tags/' + tag], cwd=repo)
    print('Attested service snapshot published.'); return 0


if __name__ == '__main__':
    try: sys.exit(main())
    except Hold as exc:
        message = 'Held: ' + str(exc)
        print(message, file=sys.stderr)
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a', encoding='utf-8') as stream: stream.write(message + '\n')
        sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print('Held: invalid input or operational failure; details withheld.', file=sys.stderr)
        sys.exit(1)
