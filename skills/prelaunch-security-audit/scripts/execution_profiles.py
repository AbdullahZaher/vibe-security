#!/usr/bin/env python3
"""Two-axis execution assessment and a deny-only static host. Never a sandbox.

Only an embedding host may supply attest(); JSON inputs cannot supply trust.
This module never executes proposed commands or implements an isolated runner.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from audit_artifacts import load_json, trusted_root

EFFECTS = {'observe', 'verify_local', 'network_read', 'modify_local', 'external_write', 'destructive'}
PROFILES = {'static-only', 'isolated-local', 'authorized-staging'}
CONTROLS = frozenset({'filesystem', 'secrets', 'sockets', 'network_egress', 'resource_limits',
                      'subprocesses', 'disposable_data'})


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class HostAttestation:
    """Return from trusted host code, never deserialize this from target data.

    The host must verify user consent and OS controls itself. A host bug or a
    malicious callback is outside this module's trust boundary.
    """
    request_sha256: str
    authorization_ref: str
    isolation_ref: str = ''
    enforced_controls: frozenset[str] = frozenset()
    command_sha256: str = ''
    spec_sha256: str = ''


def validate_request(request):
    expected = {'id', 'target', 'revision', 'effect', 'profile', 'operation', 'destination', 'paths'}
    optional = {'command', 'spec_sha256', 'authorization_ref'}
    if not isinstance(request, dict) or not (expected <= set(request) <= (expected | optional)):
        raise ValueError('request must have exactly the documented fields; approval flags are not authority')
    if any(not isinstance(request[k], str) or not request[k].strip()
           for k in ('id', 'target', 'revision', 'effect', 'profile', 'operation')):
        raise ValueError('missing action identity')
    if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', request['revision']):
        raise ValueError('revision must be immutable Git SHA')
    if request['effect'] not in EFFECTS or request['profile'] not in PROFILES:
        raise ValueError('unknown effect or profile')
    if not isinstance(request['destination'], str) or not isinstance(request['paths'], list):
        raise ValueError('invalid destination or paths')
    if any(not isinstance(p, str) or not p for p in request['paths']):
        raise ValueError('invalid path')
    if 'command' in request:
        if not isinstance(request['command'], list) or not request['command'] or any(
            not isinstance(c, str) or not c.strip() for c in request['command']
        ):
            raise ValueError('command must be a non-empty list of non-empty strings')
    if 'spec_sha256' in request:
        if not isinstance(request['spec_sha256'], str) or not request['spec_sha256'].strip():
            raise ValueError('spec_sha256 must be a non-empty string')
    if 'authorization_ref' in request:
        if not isinstance(request['authorization_ref'], str) or not request['authorization_ref'].strip():
            raise ValueError('authorization_ref must be a non-empty string')
    if request['effect'] in {'network_read', 'external_write'} and not request['destination']:
        raise ValueError('remote operation needs exact destination')
    if request['effect'] in {'observe', 'verify_local', 'modify_local'} and not request['paths']:
        raise ValueError('local operation needs exact paths')


def assess(request, *, attest=None):
    """Assess exact scope. Calling this function NEVER authorizes an execution."""
    validate_request(request)
    result = {'status': 'not_verified', 'request_sha256': digest(request),
              'execution_performed': False, 'reason': 'trusted host authorization unavailable'}
    if request['effect'] == 'destructive':
        return {**result, 'status': 'blocked', 'reason': 'destructive effects require a separate supervised workflow'}
    if request['profile'] == 'static-only' and request['effect'] != 'observe':
        return {**result, 'status': 'blocked', 'reason': 'static-only permits no target code or side effects'}
    if request['profile'] == 'authorized-staging' and request['effect'] in {'verify_local', 'modify_local'}:
        return {**result, 'status': 'blocked',
                'reason': 'staging permission is not local execution or local-write isolation'}
    if attest is None:
        return result
    authority = attest(dict(request))
    if (not isinstance(authority, HostAttestation) or authority.request_sha256 != digest(request)
            or not authority.authorization_ref):
        return result
    if authority.command_sha256:
        cmd = request.get('command')
        if not cmd or digest(cmd) != authority.command_sha256:
            return {**result, 'reason': 'command does not match authorized command_sha256'}
    if authority.spec_sha256:
        spec_sha = request.get('spec_sha256')
        if not spec_sha or spec_sha != authority.spec_sha256:
            return {**result, 'reason': 'execution specification does not match authorized spec_sha256'}
    if request['effect'] in {'verify_local', 'modify_local', 'network_read', 'external_write'}:
        if (request['profile'] != 'isolated-local' or not authority.isolation_ref
                or not CONTROLS <= authority.enforced_controls):
            return {**result, 'reason': 'required OS-enforced isolation controls not verified'}
    return {**result, 'status': 'eligible_for_host_dispatch',
            'reason': 'host verified exact action; host must enforce controls at dispatch',
            'authorization_ref': authority.authorization_ref,
            'isolation_ref': authority.isolation_ref or None}


class StaticHost:
    """Minimal host broker: only allowlisted source reads, no arbitrary execution.

    Fresh private logs belong outside target-controlled directories. events are
    observations by this controller, not proof about another host or real model.
    """
    def __init__(self, root: Path, paths: list[str], *, target: str, revision: str):
        self.root = Path(root)
        self.paths = frozenset(paths)
        self.target, self.revision = target, revision
        self.events = []

    def dispatch(self, request):
        event = {'sequence': len(self.events) + 1, 'request_sha256': digest(request),
                 'origin': 'static_host_controller', 'occurred': False, 'blocked': True}
        self.events.append(event)
        try:
            validate_request(request)
            if (request['effect'] != 'observe' or request['profile'] != 'static-only'
                    or request['operation'] != 'read_source' or request['destination']
                    or request['target'] != self.target or request['revision'] != self.revision
                    or len(request['paths']) != 1):
                raise ValueError('operation outside static host capability')
            path = request['paths'][0]
            if path not in self.paths:
                raise ValueError('path outside host allowlist')
            parts = PurePosixPath(path).parts
            if (not parts or path.startswith('/') or '\\' in path
                    or any(p in {'.', '..'} for p in path.split('/'))
                    or str(PurePosixPath(path)) != path):
                raise ValueError('noncanonical path')
            # Component-wise O_NOFOLLOW closes parent-symlink and TOCTOU escapes.
            # Unsupported platforms fail closed; do not substitute resolve()+open().
            # Only immutable system links in the operator root are canonicalized.
            if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
                raise ValueError('safe file-descriptor traversal unavailable')
            root = trusted_root(self.root)
            directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in (*root.parts[1:], *parts[:-1]):
                    if part in {'.', '..'}:
                        raise ValueError('noncanonical root')
                    next_directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                             dir_fd=directory)
                    os.close(directory)
                    directory = next_directory
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, 'rb') as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError('source must be regular file')
                    raw = source.read(1_000_001)
                    if len(raw) > 1_000_000:
                        raise ValueError('source too large')
            finally:
                os.close(directory)
            value = raw.decode('utf-8')
            event.update(occurred=True, blocked=False, effect='observe',
                         result_sha256=hashlib.sha256(raw).hexdigest())
            return {'content': value}
        except (ValueError, OSError, UnicodeError):
            # Do not log attacker-controlled strings or path errors containing secrets.
            event['reason'] = 'outside_capability_or_invalid_source'
            return {'error': 'DENIED by static host'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = assess(load_json(args.request))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 2  # CLI has no trusted host authorization adapter.


if __name__ == '__main__':
    raise SystemExit(main())
