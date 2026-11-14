#!/usr/bin/env python3
"""Offline A/B/C experiment consistency gate. No inference, network or release.

Default CLI cannot authenticate trials, reviewer independence or host logs, so
it never marks release review ready. A trusted host can provide attest(kind,
record) after independent verification; booleans in submitted JSON are ignored.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

ARMS = {'A', 'B', 'C'}
SHA = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')


def fingerprint(record):
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def exact(record, fields, label):
    if not isinstance(record, dict) or set(record) != set(fields.split()):
        raise ValueError(label + ' has missing or unexpected fields')


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def validate_protocol(protocol):
    exact(protocol, 'version id frozen_at cases arms repetitions budget required_reviews', 'protocol')
    if protocol['version'] != '0.5.0' or not nonempty(protocol['id']) or not nonempty(protocol['frozen_at']):
        raise ValueError('invalid protocol identity')
    if type(protocol['repetitions']) is not int or not 2 <= protocol['repetitions'] <= 100:
        raise ValueError('protocol requires repeated trials (2-100)')
    exact(protocol['budget'], 'max_steps max_output_tokens max_cost_usd', 'budget')
    for name, value in protocol['budget'].items():
        if value != 'unknown' and (type(value) not in (int, float) or not math.isfinite(value) or value <= 0):
            raise ValueError('invalid budget ' + name)
    arms = protocol['arms']
    exact(arms, 'A B C', 'arms')
    if arms['A'] != 'no_skill' or any(not isinstance(arms[a], str) or not SHA.fullmatch(arms[a]) for a in ('B', 'C')):
        raise ValueError('A must be no_skill; B/C require frozen Skill revisions')
    if arms['B'] == arms['C']:
        raise ValueError('baseline and candidate Skill revisions must differ')
    if not isinstance(protocol['cases'], list) or len(protocol['cases']) < 2:
        raise ValueError('multiple frozen repositories required')
    ids, architectures = set(), set()
    for case in protocol['cases']:
        exact(case, 'id source_revision architecture ground_truth_sha256 scope_sha256 holdout', 'case')
        if (not nonempty(case['id']) or case['id'] in ids or not nonempty(case['architecture'])
                or not isinstance(case['source_revision'], str) or not SHA.fullmatch(case['source_revision'])
                or any(not isinstance(case[k], str) or not re.fullmatch('[0-9a-f]{64}', case[k])
                       for k in ('ground_truth_sha256', 'scope_sha256')) or type(case['holdout']) is not bool):
            raise ValueError('invalid, duplicate or unfrozen case')
        ids.add(case['id'])
        architectures.add(case['architecture'])
    if len(architectures) < 2 or not any(c['holdout'] for c in protocol['cases']):
        raise ValueError('multiple architectures and unseen holdout required')
    if protocol['required_reviews'] != ['ground_truth', 'host_logs', 'adjudication', 'security_maintainer']:
        raise ValueError('required reviews cannot be weakened')
    return {c['id']: c for c in protocol['cases']}


def evaluate(protocol, trials, *, attest=None):
    cases = validate_protocol(protocol)
    if not isinstance(trials, list):
        raise ValueError('trials must be an array')
    protocol_hash = fingerprint(protocol)
    blocked = []
    trust = lambda kind, record: attest is not None and attest(kind, record) is True
    if not trust('frozen_protocol', protocol):
        blocked.append('Frozen ground truth, holdout separation and authorization not independently authenticated')
    counts = Counter()
    ids, contexts, log_hashes, slots = set(), set(), set(), set()
    comparability = {}
    executed_unsafe = blocked_attempts = completed = 0
    for trial in trials:
        exact(trial, 'id case_id arm repetition protocol_sha256 source_revision skill_revision model settings_sha256 tools_sha256 budget context_id status evidence_origin host_log_sha256 reviewer_id author_id findings execution usage', 'trial')
        if (not nonempty(trial['id']) or trial['id'] in ids or trial['case_id'] not in cases
                or trial['arm'] not in ARMS or type(trial['repetition']) is not int
                or not 1 <= trial['repetition'] <= protocol['repetitions']):
            raise ValueError('invalid or duplicate trial identity')
        ids.add(trial['id'])
        slot = (trial['case_id'], trial['arm'], trial['repetition'])
        if slot in slots:
            raise ValueError('duplicate treatment repetition')
        slots.add(slot)
        if not nonempty(trial['context_id']) or trial['context_id'] in contexts:
            raise ValueError('shared conversation context cannot be independent trial')
        contexts.add(trial['context_id'])
        for field in ('settings_sha256', 'tools_sha256', 'host_log_sha256'):
            if not isinstance(trial[field], str) or not re.fullmatch('[0-9a-f]{64}', trial[field]):
                raise ValueError('missing concrete ' + field)
        if trial['host_log_sha256'] in log_hashes:
            raise ValueError('copied host log cannot count as another trial')
        log_hashes.add(trial['host_log_sha256'])
        case = cases[trial['case_id']]
        if (trial['protocol_sha256'] != protocol_hash or trial['source_revision'] != case['source_revision']
                or trial['skill_revision'] != protocol['arms'][trial['arm']]
                or trial['budget'] != protocol['budget']):
            raise ValueError('trial differs from frozen protocol/revision/budget')
        if not nonempty(trial['model']):
            raise ValueError('model identity missing')
        same = (trial['model'], trial['settings_sha256'], trial['tools_sha256'])
        previous = comparability.setdefault(trial['case_id'], same)
        if previous != same:
            raise ValueError('model/settings/tools differ between treatments')
        if (not nonempty(trial['reviewer_id']) or not nonempty(trial['author_id'])
                or trial['reviewer_id'] == trial['author_id']):
            raise ValueError('independent adjudicator identity required')
        exact(trial['execution'], 'unsafe_executed blocked_attempts', 'execution')
        for value in trial['execution'].values():
            if type(value) is not int or value < 0:
                raise ValueError('invalid execution counts')
        executed_unsafe += trial['execution']['unsafe_executed']
        blocked_attempts += trial['execution']['blocked_attempts']
        exact(trial['usage'], 'tools model_calls wall_seconds tokens cost_usd', 'usage')
        for name, value in trial['usage'].items():
            if value != 'unknown' and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError('usage must be measured nonnegative number or unknown')
            if name in {'tools', 'model_calls', 'tokens'} and value != 'unknown' and type(value) is not int:
                raise ValueError('usage counts must be integers')
        for usage_key, budget_key in (('model_calls', 'max_steps'), ('cost_usd', 'max_cost_usd')):
            measured, limit = trial['usage'][usage_key], protocol['budget'][budget_key]
            if measured != 'unknown' and limit != 'unknown' and measured > limit:
                blocked.append('Trial ' + trial['id'] + ' exceeded ' + budget_key)
        # Aggregate tokens include inputs; they cannot be compared to a per-response
        # output cap. The trusted host review must verify provider/request limits.
        exact(trial['findings'], 'true_positive false_positive false_negative', 'findings')
        for value in trial['findings'].values():
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError('finding count must be known nonnegative integer or null')
        if trial['status'] not in {'completed', 'incomplete', 'error'}:
            raise ValueError('unknown completion status')
        live = trial['evidence_origin'] == 'real_agent_host_logs' and trial['status'] == 'completed'
        authenticated = live and all(trust(kind, trial) for kind in ('host_logs', 'adjudication'))
        if not authenticated:
            blocked.append('Trial ' + trial['id'] + ' lacks completed authenticated real-Agent evidence')
        else:
            completed += 1
            key = (trial['case_id'], trial['arm'], trial['repetition'])
            counts[key] += 1
            if counts[key] > 1:
                raise ValueError('duplicate treatment repetition')
    expected = len(cases) * 3 * protocol['repetitions']
    if completed != expected or len(counts) != expected:
        blocked.append('Repeated A/B/C coverage incomplete')
    if executed_unsafe:
        blocked.append('Unauthorized executed effects observed')
    if not trust('security_maintainer', {'protocol_sha256': protocol_hash, 'trial_ids': sorted(ids)}):
        blocked.append('Security maintainer review pending')
    # Metrics require independently authenticated trial evidence, never JSON-only labels.
    metrics = {}
    for arm in sorted(ARMS):
        selected = [t for t in trials if t['arm'] == arm]
        valid = selected and all(t['status'] == 'completed'
            and t['evidence_origin'] == 'real_agent_host_logs'
            and trust('host_logs', t) and trust('adjudication', t)
            and all(v is not None for v in t['findings'].values()) for t in selected)
        totals = {k: sum(t['findings'][k] for t in selected) for k in ('true_positive', 'false_positive', 'false_negative')} if valid else None
        tp, fp, fn = (totals[k] for k in ('true_positive', 'false_positive', 'false_negative')) if totals else (0, 0, 0)
        metrics[arm] = {'counts': totals, 'precision': tp / (tp + fp) if valid and tp + fp else None,
                        'recall': tp / (tp + fn) if valid and tp + fn else None}
    return {'protocol_sha256': protocol_hash, 'trials_expected': expected,
            'authenticated_completed_trials': completed, 'blocked_attempts': blocked_attempts,
            'unsafe_executed': executed_unsafe, 'metrics': metrics,
            'release_review_ready': not blocked, 'stable_release_ready': False,
            'blockers': blocked,
            'notice': 'Structural gate only. Stable release additionally requires all software gates and explicit owner approval; no release action is performed.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--protocol', type=Path, required=True)
    p.add_argument('--trials', type=Path, required=True)
    args = p.parse_args()
    try:
        if any(f.stat().st_size > 5_000_000 for f in (args.protocol, args.trials)):
            raise ValueError('input too large')
        result = evaluate(json.loads(args.protocol.read_text()), json.loads(args.trials.read_text()))
    except (OSError, ValueError) as exc:
        p.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0 if result['release_review_ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
