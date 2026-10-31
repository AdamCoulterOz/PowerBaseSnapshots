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
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8'), parse_constant=reject_constant, object_pairs_hook=unique_pairs)


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value): raise Hold('Sentinel version is not a numeric four-part version.')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise Hold('Authentication or sentinel redirect rejected.')


def token_for(base):
    mode = os.environ.get('POWERSPEC_AUTH_MODE', 'cli')
    if mode == 'cli':
        data = execute(['az', 'account', 'get-access-token', '--resource', base, '--output', 'json'])
        token = json.loads(data.stdout).get('accessToken')
    elif mode == 'github-oidc':
        tenant=os.environ.get('POWERSPEC_AZURE_TENANT_ID','')
        client=os.environ.get('POWERSPEC_AZURE_CLIENT_ID','')
        request_url=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL','')
        bearer=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
        guid=r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        if not re.fullmatch(guid,tenant) or not re.fullmatch(guid,client) or not bearer:
            raise Hold('GitHub OIDC configuration unavailable.')
        url=urllib.parse.urlsplit(request_url)
        query=urllib.parse.parse_qsl(url.query,keep_blank_values=True)
        if (url.scheme!='https' or not url.hostname or not url.hostname.endswith('.actions.githubusercontent.com')
                or url.netloc.lower()!=url.hostname.lower() or url.username or url.password or url.fragment
                or not url.path.startswith('/') or any(key.lower()=='audience' for key,_ in query)):
            raise Hold('Invalid GitHub OIDC endpoint.')
        query.append(('audience','api://AzureADTokenExchange'))
        assertion_url=urllib.parse.urlunsplit((url.scheme,url.netloc,url.path,urllib.parse.urlencode(query),''))
        opener=urllib.request.build_opener(NoRedirect())
        try:
            req=urllib.request.Request(assertion_url,headers={'Authorization':'Bearer '+bearer,'Accept':'application/json'})
            with opener.open(req,timeout=60) as response:
                if response.status!=200:raise Hold('GitHub OIDC assertion request failed.')
                assertion_data=json.load(response)
            assertion=assertion_data.get('value') if isinstance(assertion_data,dict) else None
            if not isinstance(assertion,str) or not assertion: raise Hold('GitHub OIDC assertion unavailable.')
            form=urllib.parse.urlencode({'client_id':client,'scope':base+'/.default','grant_type':'client_credentials',
                'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion}).encode()
            req=urllib.request.Request('https://login.microsoftonline.com/'+tenant+'/oauth2/v2.0/token',data=form,
                    headers={'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})
            with opener.open(req,timeout=60) as response:
                if response.status!=200:raise Hold('GitHub OIDC token exchange failed; details withheld.')
                token_data=json.load(response)
            token=token_data.get('access_token') if isinstance(token_data,dict) else None
        except (OSError,ValueError,TypeError,urllib.error.HTTPError):
            raise Hold('GitHub OIDC token exchange failed; details withheld.') from None
    else:
        raise Hold('Unsupported authentication mode.')
    if not isinstance(token,str) or not token: raise Hold('Azure token unavailable.')
    return token


def sentinel(origin):
    url = urllib.parse.urlsplit(origin)
    if (url.scheme != 'https' or not url.hostname or not url.hostname.endswith('.dynamics.com')
            or url.netloc.lower() != url.hostname.lower() or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/')):
        raise Hold('Invalid sentinel origin.')
    base = 'https://' + url.netloc
    for attempt in range(2):
        token = token_for(base)
        request = urllib.request.Request(base + '/api/data/v9.2/RetrieveVersion()', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
                if response.status != 200:raise Hold('Sentinel version request failed.')
                body=json.load(response)
                return version(body.get('Version') if isinstance(body,dict) else None)
        except urllib.error.HTTPError as exc:
            status=exc.code;exc.close()
            if status==401 and attempt==0:continue
            raise Hold('Sentinel version request failed.') from None
        except (OSError, ValueError, TypeError):
            raise Hold('Sentinel version request failed.') from None


def oidc_identity_check(origin, expected_version):
    """Use a second OIDC token for a bounded, identity-bound read proof."""
    base=origin.rstrip('/');token=token_for(base);opener=urllib.request.build_opener(NoRedirect())
    def read(label,path):
        request=urllib.request.Request(base+'/api/data/v9.2/'+path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
        try:
            with opener.open(request,timeout=60) as response:
                if response.status != 200:raise Hold(f'OIDC read proof failed: {label} HTTP {response.status}.')
                body=json.load(response)
        except urllib.error.HTTPError as exc:
            status=exc.code;exc.close()
            raise Hold(f'OIDC read proof failed: {label} HTTP {status}.') from None
        except (OSError,ValueError,TypeError):
            raise Hold(f'OIDC read proof failed: {label}; details withheld.') from None
        if not isinstance(body,dict):raise Hold(f'OIDC read proof returned invalid {label} data.')
        return body
    ident=read('WhoAmI','WhoAmI()').get('UserId')
    guid=r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    if not isinstance(ident,str) or not re.fullmatch(guid,ident):raise Hold('OIDC identity response invalid.')
    application=read('system user','systemusers('+ident+')?$select=applicationid').get('applicationid')
    expected=os.environ.get('POWERSPEC_AZURE_CLIENT_ID','')
    if not isinstance(application,str) or not re.fullmatch(guid,application) or application.casefold()!=expected.casefold():
        raise Hold('OIDC application identity did not match the configured client.')
    probes=(('file uploads','msdyn_fileuploads?$select=msdyn_fileuploadid&$top=1','msdyn_fileuploadid'),
            ('plugin steps','sdkmessageprocessingsteps?$select=sdkmessageprocessingstepid&$top=1','sdkmessageprocessingstepid'),
            ('data sources','entitydatasources?$select=entitydatasourceid&$top=1','entitydatasourceid'))
    for label,path,primary in probes:
        rows=read(label,path).get('value')
        if (not isinstance(rows,list) or len(rows)>1 or any(not isinstance(row,dict) or not isinstance(row.get(primary),str)
                or not re.fullmatch(guid,row[primary]) for row in rows)):
            raise Hold(f'OIDC read proof returned invalid {label} data.')
    entity=read('custom control metadata',"EntityDefinitions(LogicalName='customcontrol')?$select=LogicalName,PrimaryIdAttribute")
    if entity.get('LogicalName')!='customcontrol' or not isinstance(entity.get('PrimaryIdAttribute'),str) or not entity['PrimaryIdAttribute']:
        raise Hold('OIDC read proof returned invalid custom control metadata.')
    after=version(read('final version','RetrieveVersion()').get('Version'))
    if after!=expected_version:raise Hold('Sentinel version changed during OIDC read proof.')


def config(path):
    c = load(path)
    if c.get('schemaVersion') != 1 or c.get('producerRepository') != 'AdamCoulterOz/PowerSpec' or not PROFILE.fullmatch(c.get('profile', '')):
        raise Hold('Invalid pipeline configuration.')
    return c


def qualify(c, producer):
    if not SHA.fullmatch(c.get('producerCommit') or '') or not SHA256.fullmatch(c.get('approvedPolicySha256') or ''):
        raise Hold('Producer revision and approved publication policy are not configured.')
    policy = producer / 'tools/PowerSpec.Baseline/public-projection-policy.json'
    if _safe_digest(producer, 'tools/PowerSpec.Baseline/public-projection-policy.json') != c['approvedPolicySha256']:
        raise Hold('Producer policy differs from approved policy.')
    data = load(policy)
    if data.get('publicationApproved') is not True:
        raise Hold('Producer policy is not approved.')


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


REQUIRED_GATES = ('configurationSource', 'representationIdentity', 'normalizationLossAccounting',
                  'publicFieldPolicy', 'reproducibility')


def public_index(root):
    digest, files = tree_hash(root)
    for item in files:
        path = item['path']
        if ('\\' in path or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/'))):
            raise Hold('Unsafe public path.')
    names = [item['path'].casefold() for item in files]
    if len(names) != len(set(names)): raise Hold('Duplicate public paths.')
    manifest = _safe_json(root, 'manifest.json')
    if set(manifest) != {'schemaVersion', 'documents'} or manifest['schemaVersion'] != 1 or not isinstance(manifest['documents'], list):
        raise Hold('Invalid public manifest.')
    index = {}
    for doc in manifest['documents']:
        if not isinstance(doc, dict) or set(doc) != {'path', 'sha256'}:
            raise Hold('Invalid public manifest entry.')
        path = doc['path']
        if not isinstance(path, str) or not path or '\\' in path or path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')) or path.casefold() in index or path.casefold() == 'manifest.json':
            raise Hold('Unsafe public manifest path.')
        index[path.casefold()] = (path, doc['sha256'])
    actual = {item['path'].casefold(): (item['path'], item['sha256']) for item in files if item['path'] != 'manifest.json'}
    if index != actual: raise Hold('Public manifest does not match subtree.')
    return digest, files, {value[0]:value[1] for value in index.values()}


def verify_publication(root, c, v, attestation):
    digest, files, _ = public_index(root)
    expected = {'schemaVersion': 1, 'kind': 'raw-baseline-publication-attestation-v1',
                'producerCommit': c['producerCommit'], 'policySha256': c['approvedPolicySha256'],
                'profile': c['profile'], 'sourceVersionBefore': v, 'sourceVersionAfter': v,
                'inventoryConsistency': 'matched-non-atomic', 'coverageSchemaVersion': 2,
                'coverageComplete': True, 'requiredGateResults': {key: True for key in REQUIRED_GATES},
                'scopeUnresolvedMembershipRows': 0, 'publicSubtreeSha256': digest, 'publicFiles': files}
    if (attestation != expected or type(attestation.get('schemaVersion')) is not int
            or type(attestation.get('coverageSchemaVersion')) is not int
            or type(attestation.get('scopeUnresolvedMembershipRows')) is not int
            or any(type(item.get('bytes')) is not int for item in attestation.get('publicFiles', []) if isinstance(item, dict))
            or attestation.get('coverageComplete') is not True
            or any(attestation.get('requiredGateResults', {}).get(k) is not True for k in REQUIRED_GATES)):
        raise Hold('Publication attestation missing or does not match approved facts.')
    return digest


def snapshot_diff(previous, current, profile, service_version):
    current_hash, _, current_docs = public_index(current)
    if previous is None:
        prior_hash, prior_docs = None, {}
    else:
        prior_hash, _, prior_docs = public_index(previous)
    added=[{'path':path,'newSha256':current_docs[path]} for path in sorted(current_docs.keys()-prior_docs.keys())]
    removed=[{'path':path,'oldSha256':prior_docs[path]} for path in sorted(prior_docs.keys()-current_docs.keys())]
    changed=[{'path':path,'oldSha256':prior_docs[path],'newSha256':current_docs[path]}
             for path in sorted(prior_docs.keys() & current_docs.keys()) if prior_docs[path]!=current_docs[path]]
    return {'schemaVersion':1,'profile':profile,'serviceVersion':service_version,
            'previousPublicSubtreeSha256':prior_hash,'currentPublicSubtreeSha256':current_hash,
            'added':added,'removed':removed,'changed':changed}

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
        raw_attestation = execute(['git', 'show', f'{commit}:versions/{c["profile"]}/{v}.attestation.json'], cwd=repo).stdout
        attestation_file = Path(tmp) / 'attestation.json'; attestation_file.write_text(raw_attestation)
        digest = verify_publication(Path(tmp) / 'contents' / 'baselines' / c['profile'], c, v, load(attestation_file))
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
    if execute(['git', 'status', '--porcelain'], cwd=target).stdout.strip(): raise Hold('Producer checkout is not clean.')
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
    parser.add_argument('--mode', choices=['check','run','diagnose','auth-check'], default='run')
    args = parser.parse_args(); repo = Path.cwd(); c = config(args.config)
    origin = os.environ.get('SENTINEL_URL', '')
    if not origin: raise Hold('Sentinel is not configured.')
    if execute(['git', 'status', '--porcelain'], cwd=repo).stdout.strip(): raise Hold('Working tree is not clean.')
    branch = execute(['git', 'branch', '--show-current'], cwd=repo).stdout.strip()
    if not branch: raise Hold('An attached publication branch is required.')
    if args.mode == 'auth-check' and os.environ.get('POWERSPEC_AUTH_MODE') != 'github-oidc': raise Hold('Authentication check requires GitHub OIDC mode.')
    v = sentinel(origin); tag = 'service/' + v
    print('Observed service version: ' + v)
    if args.mode == 'auth-check':
        oidc_identity_check(origin,v)
        print('OIDC read proof: two token exchanges; application identity matched; four capabilities passed; version bracket matched.')
        return 0
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
        if args.mode == 'run':
            qualify(c, producer)
            acquisition = private/'acquisition'; attestation_path = private/'publication-attestation.json'
            print('Stage: baseline acquisition.', flush=True)
            result = execute([sys.executable, str(cli), 'acquire-baseline', '--environment', origin,
                              '--profile', c['profile'], '--output', str(acquisition)], allowed=(0,2), phase='Acquisition')
            if result.returncode != 0: raise Hold('Baseline acquisition incomplete; publication withheld.')
            print('Stage: publication finalization.', flush=True)
            execute([sys.executable, str(cli), 'finalize-publication', '--acquisition', str(acquisition),
                     '--producer-root', str(producer), '--producer-commit', c['producerCommit'],
                     '--output', str(attestation_path)], phase='Finalization')
            if sentinel(origin) != v: raise Hold('Sentinel version changed during capture.')
            if not attestation_path.is_file() or attestation_path.is_symlink(): raise Hold('Qualified publication attestation is unavailable.')
            snapshot = acquisition/'projection'/'public'
            if any(path.is_symlink() for path in (acquisition, acquisition/'projection', snapshot)):
                raise Hold('Public subtree ancestor is a symlink.')
            if execute(['git', 'rev-parse', 'HEAD'], cwd=producer).stdout.strip() != c['producerCommit'] or execute(['git', 'status', '--porcelain'], cwd=producer).stdout.strip():
                raise Hold('Producer changed during acquisition.')
            qualify(c, producer)
            digest = verify_publication(snapshot, c, v, load(attestation_path))
        else:
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

        prior = repo/'baselines'/c['profile']
        # Revalidate source state and publication head immediately before modifying the worktree.
        if sentinel(origin) != v: raise Hold('Sentinel version changed before publication.')
        head = execute(['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.strip()
        remote = execute(['git', 'ls-remote', '--heads', 'origin', 'refs/heads/' + branch], cwd=repo).stdout.split()
        if not remote or remote[0] != head: raise Hold('Remote branch changed; retry with a fresh checkout.')
        if execute(['git', 'status', '--porcelain'], cwd=repo).stdout.strip(): raise Hold('Working tree changed during capture.')
        version_file = repo/'versions'/c['profile']/(v+'.json')
        attestation_file = version_file.with_name(v + '.attestation.json')
        diff_file = repo/'diffs'/c['profile']/(v+'.json')
        if version_file.exists() or version_file.is_symlink() or attestation_file.exists() or attestation_file.is_symlink() or diff_file.exists() or diff_file.is_symlink():
            raise Hold('Version output already exists without a verified tag.')
        for parent in (repo/'baselines', repo/'versions', repo/'diffs', prior.parent, version_file.parent, diff_file.parent):
            if parent.is_symlink(): raise Hold('Publication path contains a symlink.')
        if prior.exists() and execute(['git', 'ls-files', '--others', '--ignored', '--exclude-standard', '--', str(prior.relative_to(repo))], cwd=repo).stdout.strip():
            raise Hold('Baseline contains ignored files; refusing replacement.')
        if prior.is_symlink(): raise Hold('Baseline symlink rejected.')
        delta=snapshot_diff(prior if prior.exists() else None,snapshot,c['profile'],v)
        if delta['currentPublicSubtreeSha256'] != digest: raise Hold('Public subtree changed after verification.')
        if prior.exists(): shutil.rmtree(prior)
        prior.parent.mkdir(parents=True, exist_ok=True); shutil.copytree(snapshot, prior)
        evidence = {'profile':c['profile'], 'producerCommit':c['producerCommit'], 'policySha256':c['approvedPolicySha256'], 'serviceVersion':v, 'snapshotSha256':digest}
        version_file.parent.mkdir(parents=True, exist_ok=True); version_file.write_bytes(canonical(evidence))
        attestation_file.write_bytes(canonical(load(attestation_path)))
        diff_file.parent.mkdir(parents=True,exist_ok=True);diff_file.write_bytes(canonical(delta))
        allowed = [str(prior.relative_to(repo)), str(version_file.relative_to(repo)), str(attestation_file.relative_to(repo)), str(diff_file.relative_to(repo))]
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
