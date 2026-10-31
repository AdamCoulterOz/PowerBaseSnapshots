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


def execute(args, cwd=None, env=None, allowed=(0,), phase=None):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode not in allowed:
        if phase is not None:
            raise Hold(f'{phase} failed (exit {result.returncode}); sensitive output withheld.')
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

def verify_snapshot(root, c, v, attestation, qualification):
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
                'familyCoverage': 'complete', 'portability': 'qualified', 'provenance': 'qualified', 'publicSafety': 'qualified',
                'discoverySha256': qualification['discoverySha256'], 'inventorySha256': qualification['inventorySha256'],
                'identityCoverageSha256': qualification['identityCoverageSha256'], 'referenceClosure': 'qualified'}
    if attestation != expected: raise Hold('Publication attestation missing or does not match approved facts.')
    return digest


def _safe_digest(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise Hold('Unsafe evidence path.')
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(p in ('', '.', '..') for p in parts):
        raise Hold('Unsafe evidence path.')
    path = Path(root)
    if path.is_symlink() or not path.is_dir(): raise Hold('Unsafe evidence root.')
    for part in parts:
        path = path / part
        if path.is_symlink(): raise Hold('Evidence symlink rejected.')
    if not path.is_file(): raise Hold('Evidence file missing.')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_json(root, relative):
    _safe_digest(root, relative)
    return load(Path(root) / relative)


def _safe_summary(values, references_evaluated=False):
    # Only validated nonnegative integers and fixed labels are written to logs.
    message = ('Component inventory: in use={inUse}, unresolved={unresolved}, ambiguous={ambiguous}; '
               'export supported={supported}, partial={partial}, unsupported={unsupported}, '
               'excluded={excluded}, unregistered={unregistered}; identity unregistered={identityMissing}, '
               'partial={identityPartial}, ambiguous={identityAmbiguous}.').format(**values)
    if references_evaluated:
        message += (' Reference evidence: missing={referencesMissing}, ambiguous={referencesAmbiguous}, '
                    'invalid={referencesInvalid}.').format(**values)
    else:
        message += ' Reference completeness not evaluated.'
    print(message)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as stream: stream.write(message + '\n')


SDK_FALLBACK = {15:'EntityKeyAttribute', 30:'ProcessTrigger', 80:'AppModule', 88:'AppModuleToRoleMap',
                171:'ProfileEntityAccessLevel', 172:'ChannelAccessProfile', 181:'EntityDataProvider',
                183:'EntityDataSource', 270:'SolutionComponentDefinition'}
SDK_EVIDENCE = {'product':'Microsoft Power Platform CLI', 'version':'2.5.1',
                'packageUrl':'https://www.nuget.org/packages/Microsoft.PowerApps.CLI.Tool/2.5.1',
                'assembly':'SolutionPackagerLib.dll',
                'assemblySha256':'719c9c6e7d056980b926692f1225d42bc1b21239335394bd00f8bcb513936b43',
                'enum':'Microsoft.Crm.Tools.SolutionPackager.ComponentType',
                'decompiledSourceSha256':'afe394758fdd8a840c644e3d2955c32907eda5dd51b9291ebcd92c4f951f41b5'}

def _catalogue_identity(entry, profile):
    code = entry['componentType']
    definitions = entry.get('definitions', [])
    labels = entry.get('optionLabels', [])
    if not isinstance(definitions, list) or not isinstance(labels, list): raise Hold('Invalid catalogue identity evidence.')
    candidates = set()
    if code in SDK_FALLBACK or (not definitions and any(isinstance(x, dict) and x.get('source') in ('component-options','dependent-options','required-options') for x in labels)):
        candidates.add('platform:' + str(code))
    ambiguous = len(definitions) > 1
    for definition in definitions:
        if not isinstance(definition, dict): raise Hold('Invalid catalogue definition.')
        entities = definition.get('entityDefinitions', [])
        primary = definition.get('primaryEntityName')
        if (definition.get('entityResolution') == 'matched' and isinstance(definition.get('name'), str) and definition['name']
                and isinstance(primary, str) and isinstance(entities, list) and len(entities) == 1 and isinstance(entities[0], dict)
                and isinstance(entities[0].get('logicalName'), str) and entities[0]['logicalName'].casefold() == primary.casefold()
                and re.fullmatch(r'[a-z0-9_]+', primary.casefold())):
            candidates.add('entity:' + primary.casefold())
        else:
            ambiguous = True
    if ambiguous or len(candidates) > 1: return None, 'ambiguous'
    if len(candidates) == 1: return next(iter(candidates)), 'resolved'
    return 'local:' + profile.casefold() + ':' + str(code), 'unresolved'


def verify_inventory(discovery, inventory, producer, c, v):
    capture = _safe_json(discovery, 'capture.json')
    report = _safe_json(inventory, 'inventory.json')
    provenance = _safe_json(inventory, 'provenance.json')
    catalogue_path = capture.get('catalogue', {}).get('path')
    if (provenance.get('captureSha256') != _safe_digest(discovery, 'capture.json')
            or provenance.get('catalogueSha256') != _safe_digest(discovery, catalogue_path)
            or provenance.get('catalogueSha256') != capture.get('catalogue', {}).get('sha256')
            or provenance.get('registrySha256') != _safe_digest(producer, 'tools/PowerSpec.Baseline/handler-registry.json')):
        raise Hold('Discovery inventory provenance does not match its inputs.')
    sdk_hash = _safe_digest(producer, 'tools/PowerSpec.Baseline/sdk-component-contracts.json')
    classification_hash = _safe_digest(producer, 'tools/PowerSpec.Baseline/platform_component_types.py')
    if (provenance.get('classificationVersion') != 2 or provenance.get('typeCatalogueSha256') != sdk_hash
            or provenance.get('classificationModuleSha256') != classification_hash
            or report.get('classificationVersion') != 2):
        raise Hold('Inventory classification provenance does not match reviewed inputs.')
    catalogue = _safe_json(discovery, catalogue_path)
    if (report.get('schemaVersion') != 2 or report.get('kind') != 'component-inventory-report'
            or report.get('profile') != c['profile'] or report.get('organizationVersion') != v
            or capture.get('profile') != c['profile'] or capture.get('organizationVersion') != v
            or capture.get('status') not in ('complete', 'partial')
            or report.get('discoveryComplete') not in (True, False)
            or report.get('rawInventoryConsistency', {}).get('claimedFlagsMatch') is not True):
        raise Hold('Discovery identity, version or consistency is invalid.')
    types = report.get('types'); rawtypes = catalogue.get('types')
    if not isinstance(types, list) or not isinstance(rawtypes, list) or not types:
        raise Hold('Discovery inventory types missing.')
    raw_by_code = {}
    for item in rawtypes:
        if not isinstance(item, dict) or type(item.get('componentType')) is not int or type(item.get('inUse')) is not bool or item['componentType'] in raw_by_code:
            raise Hold('Invalid discovery type evidence.')
        raw_by_code[item['componentType']] = item
    expected_identities = {code: _catalogue_identity(item, c['profile']) for code, item in raw_by_code.items()}
    identity_counts = {}
    for identity, status in expected_identities.values():
        if status == 'resolved': identity_counts[identity] = identity_counts.get(identity, 0) + 1
    expected_identities = {code: ((None, 'ambiguous') if status == 'resolved' and identity_counts[identity] > 1 else (identity, status))
                           for code, (identity, status) in expected_identities.items()}
    registry = _safe_json(producer, 'tools/PowerSpec.Baseline/handler-registry.json')
    if registry.get('schemaVersion') != 2 or not isinstance(registry.get('registrations'), list):
        raise Hold('Invalid export registry.')
    registrations = {}
    for row in registry['registrations']:
        if not isinstance(row, dict): raise Hold('Invalid export registration.')
        key = (row.get('typeIdentity'), row.get('stage'))
        if key in registrations: raise Hold('Duplicate export registration.')
        if row.get('status') == 'supported':
            proof = row.get('verification', {})
            if not isinstance(proof, dict) or proof.get('status') != 'passed' or not isinstance(proof.get('tests'), list) or not proof['tests']:
                raise Hold('Supported export registration lacks verification.')
        registrations[key] = row.get('status')
    seen = set(); active = []; counts = {k: 0 for k in ('supported', 'partial', 'unsupported', 'excluded', 'unregistered')}
    unresolved = ambiguous = 0
    for item in types:
        if not isinstance(item, dict) or type(item.get('componentType')) is not int or type(item.get('inUse')) is not bool:
            raise Hold('Invalid inventory type.')
        number = item['componentType']
        if number in seen or number not in raw_by_code or item['inUse'] is not raw_by_code[number]['inUse']: raise Hold('Inventory does not match discovery types.')
        seen.add(number)
        if number in SDK_FALLBACK:
            evidence = item.get('identityEvidence', {})
            sdk = evidence.get('sdk') if isinstance(evidence, dict) else None
            if (not isinstance(sdk, dict) or evidence.get('sdkName') != SDK_FALLBACK[number]
                    or sdk.get('typeCatalogueSha256') != sdk_hash
                    or any(sdk.get(key) != value for key, value in SDK_EVIDENCE.items())):
                raise Hold('Inventory SDK fallback evidence is invalid.')
        identity = item.get('identityStatus')
        if identity not in ('resolved', 'unresolved', 'ambiguous') or (item.get('typeIdentity'), identity) != expected_identities[number]: raise Hold('Inventory identity does not match discovery evidence.')
        if item['inUse']:
            active.append(item)
            unresolved += identity == 'unresolved'; ambiguous += identity == 'ambiguous'
            export = item.get('handlers', {}).get('export', {})
            status = export.get('status')
            if status not in counts or status != registrations.get((item.get('typeIdentity'), 'export'), 'unregistered'):
                raise Hold('Export status does not match registry.')
            counts[status] += 1
    if seen != set(raw_by_code) or not active or report.get('totals', {}).get('inUseTypes') != len(active):
        raise Hold('Discovery inventory count mismatch.')
    declared = report.get('totals', {}).get('stageStatusesInUse', {}).get('export')
    if declared != counts: raise Hold('Discovery export totals mismatch.')
    ready = (capture.get('status') == 'complete' and capture.get('inventoryComplete') is True
             and report.get('discoveryComplete') is True
             and all(report.get('rawInventoryConsistency', {}).get(k) is True for k in ('solutionsMatch', 'organizationVersionMatch', 'claimedFlagsMatch'))
             and unresolved == 0 and ambiguous == 0 and counts['supported'] == len(active))
    return report, {'inUse': len(active), 'unresolved': unresolved, 'ambiguous': ambiguous, **counts}, ready


def verify_identity(discovery, inventory_report, evidence, producer, c, v, snapshot=None):
    report = _safe_json(evidence, 'identity-coverage.json')
    provenance = _safe_json(evidence, 'provenance.json')
    capture = _safe_json(discovery, 'capture.json')
    if (report.get('schemaVersion') != 1 or report.get('kind') != 'identity-coverage'
            or report.get('profile') != c['profile'] or report.get('organizationVersion') != v
            or report.get('discoveryComplete') is not inventory_report.get('discoveryComplete')
            or provenance.get('discoveryCaptureSha256') != _safe_digest(discovery, 'capture.json')
            or provenance.get('discoveryCatalogueSha256') != _safe_digest(discovery, capture.get('catalogue', {}).get('path'))
            or provenance.get('rulesSha256') != _safe_digest(producer, 'tools/PowerSpec.Baseline/export-identity-rules.json')
            or provenance.get('packageSha256') != []):
        raise Hold('Identity coverage provenance or version is invalid.')
    expected_snapshot = _safe_digest(snapshot, 'manifest.json') if snapshot is not None else None
    expected_coverage = _safe_digest(snapshot, 'coverage.json') if snapshot is not None else None
    if provenance.get('snapshotManifestSha256') != expected_snapshot or provenance.get('snapshotCoverageSha256') != expected_coverage:
        raise Hold('Identity coverage snapshot does not match.')
    snap = report.get('snapshot')
    if snapshot is None:
        if snap is not None: raise Hold('Unexpected identity snapshot.')
    elif (not isinstance(snap, dict) or snap.get('provided') is not True or snap.get('verified') is not True
          or snap.get('profile') != c['profile'] or snap.get('organizationVersion') != v):
        raise Hold('Identity snapshot facts invalid.')
    rules = _safe_json(producer, 'tools/PowerSpec.Baseline/export-identity-rules.json')
    if rules.get('schemaVersion') != 1 or not isinstance(rules.get('rules'), list): raise Hold('Identity rule registry invalid.')
    rule_map = {}
    for rule in rules['rules']:
        if not isinstance(rule, dict) or not isinstance(rule.get('typeIdentity'), str) or rule['typeIdentity'] in rule_map or rule.get('status') not in ('partial', 'qualified'):
            raise Hold('Identity rule registry invalid.')
        rule_map[rule['typeIdentity']] = rule
    snapshot_documents = {}; snapshot_statuses = {}
    if snapshot is not None:
        snapshot_manifest = _safe_json(snapshot, 'manifest.json'); snapshot_coverage = _safe_json(snapshot, 'coverage.json')
        if not isinstance(snapshot_manifest.get('documents'), list) or not isinstance(snapshot_coverage.get('sources'), list): raise Hold('Snapshot family evidence invalid.')
        for document in snapshot_manifest['documents']:
            if not isinstance(document, dict) or not isinstance(document.get('family'), str): raise Hold('Snapshot family evidence invalid.')
            family = document['family']; snapshot_documents[family] = snapshot_documents.get(family, 0) + 1
        for source in snapshot_coverage['sources']:
            if not isinstance(source, dict): raise Hold('Snapshot family evidence invalid.')
            snapshot_statuses.setdefault(source.get('family'), []).append(source.get('status'))
    entries = report.get('types'); inv = inventory_report['types']
    if not isinstance(entries, list) or len(entries) != len(inv): raise Hold('Identity coverage types missing.')
    by_code = {x['componentType']: x for x in inv}; seen = set(); counts = {'unregistered': 0, 'partial': 0, 'ambiguous': 0, 'qualified': 0}
    blocked_declared = 0
    for item in entries:
        if not isinstance(item, dict) or type(item.get('componentType')) is not int: raise Hold('Invalid identity coverage type.')
        code = item['componentType']; baseline = by_code.get(code)
        if code in seen or baseline is None or item.get('inUse') is not baseline['inUse'] or item.get('identityStatus') != baseline['identityStatus'] or item.get('catalogueKey') != baseline.get('typeIdentity'):
            raise Hold('Identity coverage and inventory disagree.')
        seen.add(code)
        if item['inUse']:
            status = item.get('ruleStatus')
            if status not in counts: raise Hold('Invalid identity rule status.')
            rule = rule_map.get(item.get('catalogueKey'))
            family = rule.get('snapshotFamily') if rule else None
            source_states = snapshot_statuses.get(family, [])
            expected_data = 'observed' if snapshot is not None and source_states and all(x == 'complete' for x in source_states) else 'unavailable'
            expected_documents = snapshot_documents.get(family, 0) if family else 0
            if item.get('dataStatus') != expected_data or item.get('snapshotDocumentCount') != expected_documents:
                raise Hold('Identity data coverage differs from snapshot evidence.')
            declared = 'unregistered' if rule is None else rule['status']
            if item.get('declaredRuleStatus') != declared: raise Hold('Declared identity status differs from registry.')
            blocked_declared += declared != 'qualified' or item['identityStatus'] != 'resolved'
            expected = 'ambiguous' if item['identityStatus'] == 'ambiguous' else ('unregistered' if rule is None else rule['status'])
            if expected == 'qualified' and (item.get('dataStatus') != 'observed' or not item.get('snapshotDocumentCount')): expected = 'partial'
            if status != expected: raise Hold('Identity status does not match rule registry and data evidence.')
            counts[status] += 1
    summary = report.get('summary', {})
    refs = report.get('references'); identities = report.get('identities'); diagnostics = report.get('diagnostics')
    if (not isinstance(refs, list) or not isinstance(identities, list) or not isinstance(diagnostics, list)
            or summary.get('discoveredTypes') != len(entries) or summary.get('inUseTypes') != sum(counts.values())
            or summary.get('ruleStatusesInUse') != {k: n for k, n in counts.items() if n}
            or summary.get('identityCount') != len(identities) or summary.get('referenceCount') != len(refs)
            or summary.get('blockedDeclaredInUseCount') != blocked_declared
            or report.get('rulesReady') is not (blocked_declared == 0)):
        raise Hold('Identity coverage counts invalid.')
    if any(not isinstance(ref, dict) or ref.get('resolution') not in ('resolved', 'ambiguous', 'unresolved-external-or-missing', 'invalid') for ref in refs):
        raise Hold('Invalid reference evidence.')
    unresolved_refs = sum(ref['resolution'] != 'resolved' for ref in refs)
    if summary.get('unresolvedReferenceCount') != unresolved_refs: raise Hold('Reference counts invalid.')
    reference_counts = {'referencesMissing': sum(ref['resolution'] == 'unresolved-external-or-missing' for ref in refs),
                        'referencesAmbiguous': sum(ref['resolution'] == 'ambiguous' for ref in refs),
                        'referencesInvalid': sum(ref['resolution'] == 'invalid' for ref in refs)}
    return report, counts, unresolved_refs, reference_counts


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
    keyfile = Path(directory)/'deploy-key'; keyfile.write_text(key if key.endswith('\n') else key + '\n'); keyfile.chmod(0o600)
    known_hosts = Path(directory)/'known_hosts'; known_hosts.write_text(GITHUB_HOST_KEY); known_hosts.chmod(0o600)
    env = os.environ.copy()
    env['GIT_SSH_COMMAND'] = f'ssh -i {shlex.quote(str(keyfile))} -o UserKnownHostsFile={shlex.quote(str(known_hosts))} -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes'
    target = Path(directory)/'producer'
    print('Stage: producer clone.', flush=True)
    execute(['git', 'clone', '--no-checkout', '--filter=blob:none', 'git@github.com:AdamCoulterOz/PowerSpec.git', str(target)], env=env, phase='Producer clone')
    print('Stage: producer checkout.', flush=True)
    execute(['git', 'checkout', '--detach', c['producerCommit']], cwd=target, env=env, phase='Producer checkout')
    if execute(['git', 'rev-parse', 'HEAD'], cwd=target, phase='Producer revision check').stdout.strip() != c['producerCommit']: raise Hold('Producer revision mismatch.')
    keyfile.unlink()
    return target


def report_discovery_failures(discovery):
    """Expose only recognized source names and numeric HTTP status, never response text."""
    allowed = {'organization-version-before','organization-version-after','solutions-before','solutions-after',
               'component-attribute','dependent-attribute','required-attribute',
               'component-options','dependent-options','required-options','component-definitions',
               'entity-definitions','solution-components','dependency-endpoints'}
    try:
        manifest = _safe_json(discovery, 'capture.json')
        sources = manifest.get('sources', [])
        if not isinstance(sources, list): return
        for source in sources:
            if not isinstance(source, dict) or source.get('name') not in allowed or source.get('status') not in ('failed','unsupported'):
                continue
            status = source.get('failure', {}).get('httpStatus') if isinstance(source.get('failure'), dict) else None
            suffix = f'HTTP {status}' if type(status) is int and 100 <= status <= 599 else 'status unavailable'
            print(f"Discovery source {source['name']}: {suffix}.", flush=True)
    except (OSError, ValueError, TypeError, KeyError, Hold):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='pipeline/config.json'); parser.add_argument('--workdir', required=True)
    parser.add_argument('--producer', help='Optional clean, pinned local producer checkout')
    parser.add_argument('--mode', choices=['check','run','diagnose'], default='run')
    args = parser.parse_args(); repo = Path.cwd(); c = config(args.config)
    origin = os.environ.get('SENTINEL_URL', '')
    if not origin: raise Hold('Sentinel is not configured.')
    if execute(['git', 'status', '--porcelain'], cwd=repo).stdout.strip(): raise Hold('Working tree is not clean.')
    branch = execute(['git', 'branch', '--show-current'], cwd=repo).stdout.strip()
    if not branch: raise Hold('An attached publication branch is required.')
    v = sentinel(origin); tag = 'service/' + v
    print('Observed service version: ' + v)
    if args.mode != 'diagnose' and existing_tag(repo, tag, c, v): print('Already published and verified.'); return 0
    if args.mode == 'check': print('New sentinel version; publication is not yet established.'); return 0
    if not SHA.fullmatch(c.get('producerCommit') or ''): raise Hold('Producer revision is not configured.')
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
        cli = producer/'tools/PowerSpec.Baseline/baseline.py'
        discovery = private/'discovery'; inventory = private/'inventory'; preliminary = private/'identity-preflight'
        capture = private/'capture'; snapshot = private/'snapshot'; identity = private/'identity'
        print('Stage: discovery.', flush=True)
        discovery_status = execute([sys.executable, str(cli), 'discover', '--environment', origin, '--profile', c['profile'], '--output', str(discovery)], allowed=(0,1,2), phase='Discovery')
        if discovery_status.returncode != 0: report_discovery_failures(discovery)
        if discovery_status.returncode == 1: raise Hold('Discovery failed (exit 1); sensitive output withheld.')
        print('Stage: inventory.', flush=True)
        inventory_status = execute([sys.executable, str(cli), 'inventory', '--input', str(discovery), '--output', str(inventory), '--require-stage', 'export'], allowed=(0,2), phase='Inventory')
        inventory_report, counts, export_ready = verify_inventory(discovery, inventory, producer, c, v)
        print('Stage: identity preflight.', flush=True)
        coverage_status = execute([sys.executable, str(cli), 'identity-coverage', '--discovery', str(discovery), '--output', str(preliminary)], allowed=(0,2), phase='Identity preflight')
        pre_report, rule_counts, unresolved_refs, reference_counts = verify_identity(discovery, inventory_report, preliminary, producer, c, v)
        _safe_summary({**counts, 'identityMissing': rule_counts['unregistered'], 'identityPartial': rule_counts['partial'],
                       'identityAmbiguous': rule_counts['ambiguous'], **reference_counts})
        if sentinel(origin) != v: raise Hold('Sentinel version changed during discovery.')
        if args.mode == 'diagnose':
            if discovery_status.returncode != 0 or not inventory_report['discoveryComplete'] or coverage_status.returncode != 0:
                raise Hold('Discovery diagnostics are incomplete.')
            print('Diagnostic inventory produced; publication was not attempted.')
            return 0
        if discovery_status.returncode != 0 or inventory_status.returncode != 0 or coverage_status.returncode != 0 or not export_ready:
            raise Hold('Discovery identity or export coverage is incomplete.')
        # Informational coverage lacks snapshot data; use the pinned rule registry
        # to distinguish rules awaiting data from rules which are themselves unqualified.
        rules = _safe_json(producer, 'tools/PowerSpec.Baseline/export-identity-rules.json')
        entries = rules.get('rules') if rules.get('schemaVersion') == 1 else None
        if not isinstance(entries, list): raise Hold('Identity rule registry invalid.')
        by_identity = {}
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get('typeIdentity'), str) or item['typeIdentity'] in by_identity:
                raise Hold('Identity rule registry invalid.')
            by_identity[item['typeIdentity']] = item
        for item in pre_report['types']:
            if not item['inUse']: continue
            rule = by_identity.get(item.get('catalogueKey'), {})
            proof = rule.get('verification', {})
            if (item.get('identityStatus') != 'resolved' or rule.get('status') != 'qualified'
                    or not isinstance(proof, dict) or proof.get('status') != 'passed'
                    or not isinstance(proof.get('tests'), list) or not proof['tests']):
                raise Hold('Identity or reference rules are not qualified.')
        if pre_report.get('rulesReady') is not True: raise Hold('Identity or reference rules are not qualified.')
        qualify(c)
        print('Stage: capture.', flush=True)
        status = execute([sys.executable, str(cli), 'capture', '--environment', origin, '--profile', c['profile'], '--output', str(capture)], allowed=(0,2), phase='Capture')
        if status.returncode != 0: raise Hold('Capture incomplete; publication withheld.')
        verify_capture(capture, c, v)
        print('Stage: normalization.', flush=True)
        status = execute([sys.executable, str(cli), 'normalize', '--input', str(capture), '--output', str(snapshot)], allowed=(0,2), phase='Normalization')
        if status.returncode != 0: raise Hold('Normalization incomplete; publication withheld.')
        if sentinel(origin) != v: raise Hold('Sentinel version changed during capture.')
        print('Stage: identity verification.', flush=True)
        status = execute([sys.executable, str(cli), 'identity-coverage', '--discovery', str(discovery), '--snapshot', str(snapshot), '--output', str(identity), '--require-complete'], allowed=(0,2), phase='Identity verification')
        identity_report, identity_counts, unresolved_refs, reference_counts = verify_identity(discovery, inventory_report, identity, producer, c, v, snapshot)
        if (status.returncode != 0 or identity_report.get('complete') is not True or identity_counts['qualified'] != counts['inUse']
                or identity_report.get('referenceEvidenceComplete') is not True
                or identity_report.get('referenceCoverage', {}).get('snapshot', {}).get('status') != 'complete'
                or unresolved_refs or identity_report.get('diagnostics') or identity_report.get('snapshot', {}).get('coverageComplete') is not True
                or any(item.get('inUse') and (item.get('identityStatus') != 'resolved' or item.get('dataStatus') != 'observed' or not item.get('snapshotDocumentCount')) for item in identity_report['types'])):
            raise Hold('Identity or reference coverage is incomplete.')
        _safe_summary({**counts, 'identityMissing': identity_counts['unregistered'], 'identityPartial': identity_counts['partial'],
                       'identityAmbiguous': identity_counts['ambiguous'], **reference_counts}, references_evaluated=True)
        qualification = {'discoverySha256': _safe_digest(discovery, 'capture.json'),
                         'inventorySha256': _safe_digest(inventory, 'inventory.json'),
                         'identityCoverageSha256': _safe_digest(identity, 'identity-coverage.json')}
        attestation_path = private/'attestation.json'
        if not attestation_path.is_file(): raise Hold('Qualified publication attestation is unavailable.')
        digest = verify_snapshot(snapshot, c, v, load(attestation_path), qualification)
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
