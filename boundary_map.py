#!/usr/bin/env python3
"""Security Boundary Mapping: private discovery, authority analysis, and reporting.

The host coding agent performs investigation and authorized read-only provider queries.
This dependency-free CLI never executes target code or reads credential values.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
KINDS = ['principal', 'credential', 'service', 'control', 'resource', 'action']
SKIP = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', 'vendor', '.terraform'}
EXTENSIONS = {'.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rs', '.sol', '.tf', '.yaml', '.yml', '.json', '.toml', '.md', '.sh', '.dockerfile'}
ENV = re.compile(r'''(?:process\.env\.([A-Z][A-Z0-9_]*)|(?:getenv|environ\.get)\(\s*["']([A-Z][A-Z0-9_]*)["']|(?:process\.env|os\.environ)\[\s*["']([A-Z][A-Z0-9_]*)["'])''')


class ReportError(ValueError):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ReportError(f'Cannot read JSON {path}: {exc}') from exc


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def safe_file(root, relative):
    p = Path(relative)
    if p.is_absolute() or '..' in p.parts or not relative:
        raise ReportError('Evidence path must be relative without traversal')
    root = Path(root).resolve(strict=True)
    target = (root / p).resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise ReportError('Evidence escapes its root or is not a file')
    if target.name.startswith('.env') or any(part.startswith('.env') for part in p.parts) or target.suffix in {'.pem', '.key', '.p12', '.pfx'}:
        raise ReportError('Credential files cannot be used as evidence')
    return target


def evidence_record(root, path, start, end, evidence_id, root_id='repo1', kind='source', provenance='', captured_at=None):
    if kind != 'source' and not captured_at:
        raise ReportError('Deployment/attestation evidence requires its original --captured-at timestamp')
    data = safe_file(root, path).read_bytes()
    lines = data.decode('utf-8').splitlines()
    if not 1 <= start <= end <= len(lines):
        raise ReportError(f'Invalid line range {start}-{end} for {path}')
    return dict(id=evidence_id, root=root_id, path=path, start_line=start, end_line=end,
                sha256=hashlib.sha256(data).hexdigest(), kind=kind,
                captured_at=captured_at or datetime.now(timezone.utc).isoformat(), provenance=provenance)


def schema_errors(value, rule, schema, where='$'):
    if '$ref' in rule:
        return schema_errors(value, schema['$defs'][rule['$ref'].split('/')[-1]], schema, where)
    errors = []
    types = {'object': dict, 'array': list, 'string': str, 'integer': int}
    if 'type' in rule and (not isinstance(value, types[rule['type']]) or isinstance(value, bool)):
        return [f'{where}: expected {rule["type"]}']
    if 'enum' in rule and value not in rule['enum']:
        errors.append(f'{where}: expected one of {rule["enum"]}')
    if isinstance(value, dict):
        for k in rule.get('required', []):
            if k not in value:
                errors.append(f'{where}.{k}: required')
        for k, v in value.items():
            if k in rule.get('properties', {}):
                errors += schema_errors(v, rule['properties'][k], schema, f'{where}.{k}')
            elif rule.get('additionalProperties') is False:
                errors.append(f'{where}.{k}: unknown field')
    if isinstance(value, list):
        if len(value) < rule.get('minItems', 0):
            errors.append(f'{where}: requires at least {rule["minItems"]} items')
        for i, v in enumerate(value):
            errors += schema_errors(v, rule.get('items', {}), schema, f'{where}[{i}]')
    if isinstance(value, str) and len(value.strip()) < rule.get('minLength', 0):
        errors.append(f'{where}: empty value')
    if isinstance(value, int) and value < rule.get('minimum', value):
        errors.append(f'{where}: below minimum')
    return errors


def validate(report, report_path, roots):
    errors = schema_errors(report, read_json(ROOT / 'report.schema.json'), read_json(ROOT / 'report.schema.json'))
    if errors:
        return errors
    collections = {}
    for name in ['nodes', 'edges', 'boundaries', 'scenarios', 'evidence', 'coverage', 'questions']:
        items = report[name]
        collections[name] = {x['id']: x for x in items}
        if len(items) != len(collections[name]):
            errors.append(f'{name}: duplicate IDs')
    nodes, edges, evidence = (collections[k] for k in ['nodes', 'edges', 'evidence'])
    global_ids = [x['id'] for name in ['nodes', 'edges', 'boundaries', 'scenarios', 'coverage', 'questions'] for x in report[name]]
    if len(set(global_ids)) != len(global_ids):
        errors.append('IDs must be unique across graph, scenarios, coverage and questions')

    def refs(ids, pool, where):
        if len(set(ids)) != len(ids):
            errors.append(f'{where}: duplicate references')
        for i in ids:
            if i not in pool:
                errors.append(f'{where}: unknown reference {i}')

    for ev in evidence.values():
        try:
            if ev['root'] == 'artifacts':
                root = Path(report_path).parent
            else:
                root = roots[ev['root']]
            actual = evidence_record(root, ev['path'], ev['start_line'], ev['end_line'], ev['id'])
            if actual['sha256'] != ev['sha256']:
                errors.append(f'{ev["id"]}: evidence hash does not match')
            stamp = datetime.fromisoformat(ev['captured_at'].replace('Z', '+00:00'))
            if stamp.tzinfo is None:
                raise ValueError('capture time needs timezone')
            if ev['kind'] != 'source' and not ev['provenance'].strip():
                errors.append(f'{ev["id"]}: observation needs account/environment and provenance')
        except (KeyError, OSError, ValueError, UnicodeError) as exc:
            errors.append(f'{ev["id"]}: {exc}')
    envs = report['system']['environments']
    for n in nodes.values():
        refs(n['owner_ids'], nodes, n['id'] + ' owners')
        refs(n['evidence_ids'], evidence, n['id'])
        if n['environment'] not in envs and n['environment'] != 'shared':
            errors.append(f'{n["id"]}: unknown environment')
    for edge in edges.values():
        refs([edge['source'], edge['target']], nodes, edge['id'])
        refs(edge['requires_all'], nodes, edge['id'] + ' prerequisites')
        refs(edge['evidence_ids'], evidence, edge['id'])
        if edge['basis'] != 'unknown' and not edge['evidence_ids']:
            errors.append(f'{edge["id"]}: established grant needs evidence')
        if edge['basis'] == 'observed' and not any(evidence.get(e, {}).get('kind') == 'deployment' for e in edge['evidence_ids']):
            errors.append(f'{edge["id"]}: observed grant needs deployment evidence')
    for c in report['coverage']:
        refs(c['evidence_ids'], evidence, c['id'])
        if c['environment'] not in envs and c['environment'] != 'shared':
            errors.append(f'{c["id"]}: unknown environment')
        if c['status'] == 'inspected' and not c['evidence_ids']:
            errors.append(f'{c["id"]}: inspected coverage needs evidence')
    for s in report['scenarios']:
        refs(s['initial_control'], nodes, s['id'])
    for b in report['boundaries']:
        refs([b['action_id'], b['enforcer_id']], nodes, b['id'])
        refs(b['gate_ids'], edges, b['id'])
        refs(b['coverage_ids'], collections['coverage'], b['id'])
        refs(b['evidence_ids'], evidence, b['id'])
        if nodes.get(b['action_id'], {}).get('kind') != 'action':
            errors.append(f'{b["id"]}: protected target must be an action')
        incoming = {e['id'] for e in edges.values() if e['target'] == b['action_id']}
        if set(b['gate_ids']) != incoming or not incoming:
            errors.append(f'{b["id"]}: gates must enumerate every modeled incoming action path')
        if not any(evidence.get(e, {}).get('kind') == 'deployment' for e in b['evidence_ids']) and not b['remaining_checks']:
            errors.append(f'{b["id"]}: source-only boundary needs remaining deployment checks')
    for q in report['questions']:
        refs(q['affects'], {**nodes, **edges, **collections['boundaries'], **collections['coverage'], **collections['scenarios']}, q['id'])
        refs(q['evidence_ids'], evidence, q['id'])
        if q['status'] == 'resolved' and (not q['answer'].strip() or not q['evidence_ids']):
            errors.append(f'{q["id"]}: resolution needs an answer and corroborating evidence')
        if 'human_blocker' in q:
            try:
                stamp = datetime.fromisoformat(q['human_blocker']['asked_at'].replace('Z', '+00:00'))
                if stamp.tzinfo is None:
                    raise ValueError('timezone required')
            except ValueError:
                errors.append(f'{q["id"]}: human request needs an asked_at timestamp with timezone')
    # Environment discovery itself must be explicitly accounted for.
    for action in nodes.values():
        if action['kind'] == 'action' and not any(b['action_id'] == action['id'] for b in report['boundaries']):
            errors.append(f'{action["id"]}: action needs a boundary assessment')
    for env in envs:
        missing = {'system_inventory', 'source', 'deployment', 'credentials', 'administration', 'recovery', 'external_provider'} - {c['category'] for c in report['coverage'] if c['environment'] == env}
        if missing:
            errors.append(f'{env}: missing coverage categories: ' + ', '.join(sorted(missing)))
        if not any(c['environment'] == env and c['category'] == 'system_inventory' for c in report['coverage']):
            errors.append(f'{env}: missing system_inventory coverage')
    return errors or delivery_errors(report)


def reachable(report, scenario, possible=False):
    reached = set(scenario['initial_control'])
    paths = {n: 'Assumed initial compromise' for n in reached}
    changed = True
    while changed:
        changed = False
        for e in report['edges']:
            if e['basis'] != 'observed' and not possible:
                continue
            if e['source'] in reached and set(e['requires_all']) <= reached and e['target'] not in reached:
                reached.add(e['target']); paths[e['target']] = e['id']; changed = True
    return reached, paths


def assess(report, scenario):
    known, paths = reachable(report, scenario)
    possible, _ = reachable(report, scenario, True)
    coverage = {c['id']: c for c in report['coverage']}
    evidence = {e['id']: e for e in report['evidence']}
    nodes = {n['id']: n for n in report['nodes']}
    results = []
    for b in report['boundaries']:
        action = b['action_id']
        relevant = {action, b['enforcer_id']}
        changed = True
        while changed:
            before = len(relevant)
            for e in report['edges']:
                if e['target'] in relevant:
                    relevant.update([e['source'], *e['requires_all']])
            for nid in list(relevant):
                relevant.update(nodes[nid]['owner_ids'])
            changed = len(relevant) != before
        scope_coverage = set(b['coverage_ids']) | {c['id'] for c in report['coverage']
                          if c['category'] == 'system_inventory' and c['environment'] in
                          {nodes[action]['environment'], 'shared'}}
        affected = relevant | scope_coverage | {b['id'], scenario['id']} | {
            e['id'] for e in report['edges'] if e['target'] in relevant}
        unknowns = [q['id'] for q in report['questions'] if q['status'] != 'resolved' and set(q['affects']) & affected]
        incomplete = [c for c in sorted(scope_coverage) if coverage[c]['status'] != 'inspected']
        owner_gaps = [nid for nid in sorted(relevant) if nodes[nid]['kind'] in {'credential', 'control'} and not nodes[nid]['owner_ids']]
        issues, gaps = [], []

        def gap(kind, target, description, human_eligible=True):
            item = dict(id=f'{kind}:{target}', target=target, kind=kind,
                        description=description, human_eligible=human_eligible)
            if item['id'] not in {g['id'] for g in gaps}:
                gaps.append(item)
                issues.append(description)

        if action in known:
            status = 'defeated'
            issues = ['A modeled authority path reaches this action. Follow the graph edges for the prerequisites.']
        else:
            for e in report['edges']:
                if e['target'] in relevant and e['basis'] != 'observed':
                    gap('edge', e['id'], f'{e["id"]}: inspect the effective deployed grant ({e["description"]}).')
            if b['enforcer_id'] in known:
                gap('enforcer', b['id'], 'The enforcer is controlled; enumerate and assess its bypass paths.', False)
            for qid in unknowns:
                gap('question', qid, f'{qid}: reconcile the clarification and its evidence.')
            for cid in incomplete:
                gap('coverage', cid, f'{cid}: complete the {coverage[cid]["subject"]} inspection.')
            for nid in owner_gaps:
                gap('owner', nid, f'{nid}: establish who controls and recovers this authority.')
            if b['challenge'] != 'supported':
                gap('challenge', b['id'], 'Finish the challenge pass using all available evidence.', False)
            for i, check in enumerate(b['remaining_checks']):
                gap(f'check-{i + 1}', b['id'], check)
            if not any(evidence.get(e, {}).get('kind') == 'deployment' for e in b['evidence_ids']):
                gap('deployment', b['id'], 'Obtain observed deployment evidence for enforcement.')
            if scenario['review'] != 'supported':
                gap('scenario', scenario['id'], 'Review the initial compromise assumptions.', False)
            status = 'unverified' if issues else 'survives'
            if status == 'survives':
                issues = ['The reviewed model requires authority outside this compromise. Limited to this snapshot and declared coverage.']
        results.append(dict(boundary_id=b['id'], action_id=action, status=status, reasons=issues,
                            gaps=gaps, human_requests=[]))
    reachable_actions = dict.fromkeys(r['action_id'] for r in results if r['status'] == 'defeated')
    attack_paths = [attack_path(report, scenario, action_id, paths) for action_id in reachable_actions]
    return dict(id=scenario['id'], known=sorted(known), possible=sorted(possible), paths=paths,
                results=results, attack_paths=attack_paths)


def attack_path(report, scenario, action_id, paths):
    """One observed proof per reachable action, retaining every AND prerequisite.

    `reachable` records the first establishing grant, so this is a proof DAG rather
    than a claim to enumerate every alternative attack path in the system.
    """
    edges = {e['id']: e for e in report['edges']}
    initial, seen, steps = set(), set(), []

    def visit(nid):
        if nid in seen:
            return
        seen.add(nid)
        if nid in scenario['initial_control']:
            initial.add(nid)
            return
        edge = edges[paths[nid]]
        for parent in [edge['source'], *edge['requires_all']]:
            visit(parent)
        steps.append(dict(edge))

    visit(action_id)
    return dict(action_id=action_id, initial_control=sorted(initial), steps=steps)


def delivery_state(report):
    """Uncertainty is evidence state, never permission to stop investigating.

    Delivery requires every gap to have an explicit, already-asked human dependency.
    The host agent must establish that its recorded attempts exhausted available tools;
    Python validates the record and links, not the truth of that assertion.
    """
    assessments = [assess(report, s) for s in report['scenarios']]
    gaps = {g['id']: g for a in assessments for r in a['results'] for g in r['gaps']}
    # Also account for unfinished work even when a demonstrated path already defeats
    # every affected boundary. A proven bypass must not hide unrelated review gaps.
    def add(kind, target, description, human_eligible=True):
        key = f'{kind}:{target}'
        gaps.setdefault(key, dict(id=key, target=target, kind=kind,
                                 description=description, human_eligible=human_eligible))
    for q in report['questions']:
        if q['status'] != 'resolved':
            add('question', q['id'], q['question'])
    for c in report['coverage']:
        if c['status'] not in {'inspected', 'excluded'}:
            add('coverage', c['id'], f'Complete {c["subject"]}.')
    for n in report['nodes']:
        if n['kind'] in {'credential', 'control'} and not n['owner_ids']:
            add('owner', n['id'], f'Establish ownership and recovery of {n["label"]}.')
    for e in report['edges']:
        if e['basis'] != 'observed':
            add('edge', e['id'], f'Inspect effective grant {e["id"]}.')
    for s in report['scenarios']:
        if s['review'] != 'supported':
            add('scenario', s['id'], 'Review initial compromise assumptions.', False)
    for b in report['boundaries']:
        if b['challenge'] != 'supported':
            add('challenge', b['id'], 'Finish the challenge pass.', False)
        for i, check in enumerate(b['remaining_checks']):
            add(f'check-{i + 1}', b['id'], check)
    requests, errors, by_gap = [], [], {}
    for q in report['questions']:
        h = q.get('human_blocker')
        if not h or q['status'] == 'resolved':
            continue
        if q['status'] != 'open':
            errors.append(f'{q["id"]}: answer already supplied; reconcile it before delivery')
            continue
        if f'question:{q["id"]}' not in h['gap_ids']:
            errors.append(f'{q["id"]}: request must cover its own question gap')
        for gid in h['gap_ids']:
            g = gaps.get(gid)
            if not g:
                errors.append(f'{q["id"]}: human request references unknown or resolved gap {gid}')
            elif not g['human_eligible']:
                errors.append(f'{gid}: agent work cannot be delegated to a human blocker')
            elif g['target'] != q['id'] and g['target'] not in q['affects']:
                errors.append(f'{q["id"]}: request does not affect target of {gid}')
            else:
                by_gap.setdefault(gid, []).append(q['id'])
        requests.append(dict(question_id=q['id'], question=q['question'], **h))
    for gid, g in gaps.items():
        if gid not in by_gap:
            errors.append(f'Agent work remains [{gid}]: {g["description"]} '
                          'Continue investigating; only a specific human-only information/access request may block delivery.')
    for a in assessments:
        for r in a['results']:
            ids = {qid for g in r['gaps'] for qid in by_gap.get(g['id'], [])}
            r['human_requests'] = [h for h in requests if h['question_id'] in ids]
    return dict(status='investigating' if errors else 'awaiting_human' if gaps else 'complete',
                errors=errors, requests=requests, assessments=assessments)


def delivery_errors(report):
    return delivery_state(report)['errors']


def deliverable(report):
    state = delivery_state(report)
    if state['errors']:
        raise ReportError('\n'.join(state['errors']))
    return state


def discover(roots, max_files=20000):
    records, limitations = [], []
    for rid, root in roots.items():
        count = 0
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(base) / d).is_symlink())
            for name in sorted(files):
                p = Path(base) / name
                if p.is_symlink() or name.startswith('.env') or p.suffix in {'.pem', '.key', '.p12', '.pfx'}:
                    continue
                if p.suffix.lower() not in EXTENSIONS and name not in {'Dockerfile', 'Procfile', 'Makefile'}:
                    continue
                count += 1
                if count > max_files:
                    break
                relative = str(p.relative_to(root))
                categories = []
                if any(t in relative.lower() for t in ['terraform', '.github/workflows', 'docker', 'render', 'vercel', 'kubernetes', 'deploy', 'infra']):
                    categories.append('deployment')
                if any(t in relative.lower() for t in ['auth', 'permission', 'policy', 'sign', 'wallet', 'role', 'recover', 'admin']):
                    categories.append('authority')
                symbols = []
                try:
                    if p.stat().st_size <= 512000:
                        text = p.read_text(encoding='utf-8')
                        symbols = sorted({next(x for x in m if x) for m in ENV.findall(text)})
                    else:
                        limitations.append(f'{rid}/{relative}: content skipped above 512 KB')
                except (OSError, UnicodeError):
                    limitations.append(f'{rid}/{relative}: could not read text')
                records.append(dict(root=rid, path=relative, categories=categories, credential_name_candidates=symbols))
            if count > max_files:
                limitations.append(f'{rid}: file limit reached; inventory is incomplete')
                break
    return dict(files=records, limitations=limitations,
                warning='Candidates only. No deployments, credential values, permissions, or completeness have been established.')


def escape(s):
    return html.escape(str(s), quote=True)


def render(report):
    state = deliverable(report)
    assessments = state['assessments']
    nodes = {n['id']: n for n in report['nodes']}
    out = ['# Security Boundary Mapping', '', report['system']['name'], '',
           'Snapshot-based investigation, not a security certification. Unreachable in the graph does not prove impossible in the system.', '',
           'Investigation: ' + ('Waiting for specific human input' if state['status'] == 'awaiting_human' else 'Review complete within the declared scope'), '',
           '## Attack paths found', '']
    found = False
    for s, a in zip(report['scenarios'], assessments):
        for path in a['attack_paths']:
            found = True
            out += [f'### {escape(s["label"])} → {escape(nodes[path["action_id"]]["label"])}', '',
                    'Assumed starting access: ' + escape(', '.join(nodes[n]['label'] for n in path['initial_control'])), '']
            if not path['steps']:
                out += ['The action is already included in the assumed starting access; no additional grant is needed.', '']
            for step in path['steps']:
                required = [step['source'], *step['requires_all']]
                out += ['- ' + escape(' AND '.join(nodes[n]['label'] for n in required)) + ' → ' +
                        escape(nodes[step['target']]['label']) + ': ' + escape(step['description']) +
                        ' (evidence: ' + escape(', '.join(step['evidence_ids'])) + ')']
            out += ['', 'One observed authority path under this scenario, not a demonstrated exploit or an exhaustive list of alternatives.', '']
    if not found:
        out += [('No attack paths found within the reviewed scope.' if state['status'] == 'complete' else
                 'No attack paths established yet. Specific input is still required to finish the investigation.'), '']
    out += ['## Specific input required', '']
    if state['requests']:
        for h in state['requests']:
            out += [f'### {h["question_id"]}: {h["request"]}', '',
                    'Requested from: ' + escape(h['requested_from']), '',
                    'Why the agent cannot obtain it: ' + escape(h['why_agent_cannot_resolve']), '',
                    'Already checked: ' + escape('; '.join(h['attempted_checks'])), '',
                    'Resolves: ' + escape(', '.join(h['gap_ids'])), '']
    else:
        out += ['No outstanding human requests.', '']
    out += ['## Supporting evidence for ruled-out paths', '',
            '| Compromise | Action investigated | Why this path was ruled out |', '| --- | --- | --- |']
    for s, a in zip(report['scenarios'], assessments):
        for r in a['results']:
            if r['status'] == 'survives':
                vals = [s['label'], nodes[r['action_id']]['label'], ' '.join(r['reasons'])]
                out.append('| ' + ' | '.join(escape(v).replace('|', '\\|') for v in vals) + ' |')
    for title, key in [('System coverage', 'coverage'), ('Clarifications', 'questions'), ('Authority inventory', 'nodes'), ('Evidence', 'evidence')]:
        out += ['', '## ' + title, '', '```json', json.dumps(report[key], indent=2), '```']
    return '\n'.join(out) + '\n'


def render_html(report):
    state = deliverable(report)
    data = json.dumps(dict(report=report, assessments=state['assessments'],
                          investigation_status=state['status'], human_requests=state['requests'])).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    template = (ROOT / 'viewer.html').read_text(encoding='utf-8')
    return template.replace('/*REPORT_DATA*/null', data)


def roots_from_args(values):
    roots = {}
    for i, value in enumerate(values or [], 1):
        rid, path = value.split('=', 1) if '=' in value else (f'repo{i}', value)
        if rid in roots or rid == 'artifacts' or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', rid):
            raise ReportError('Repository IDs must be unique identifiers; artifacts is reserved')
        root = Path(path).resolve(strict=True)
        if not root.is_dir():
            raise ReportError('Repository root must be a directory')
        roots[rid] = root
    return roots


def initialize(args, roots):
    out = Path(args.out).resolve()
    if any(out == r or out.is_relative_to(r) for r in roots.values()):
        raise ReportError('Keep private review output outside the source repositories')
    out.mkdir(parents=True, exist_ok=False)
    report = dict(report_version='2', system=dict(name=args.name, environments=args.environment or ['production'], exclusions=[]),
                  nodes=[], edges=[], boundaries=[], scenarios=[], coverage=[], evidence=[], questions=[])
    write_json(out / 'report.json', report)
    write_json(out / 'discovery.json', discover(roots))
    write_json(out / 'workspace.json', {'repositories': {k: str(v) for k, v in roots.items()}})
    instructions = '# Map the entire application\n\nTool directory: ' + str(ROOT) + '\nReview directory: ' + str(out) + '\n\n'
    instructions += 'Read workspace.json, discovery.json, report.json, the schema and REPORT_FORMAT.md.\n\n'
    instructions += '\n\n'.join((ROOT / 'prompts' / name).read_text() for name in ['discover.md', 'providers.md', 'map.md', 'challenge.md'])
    (out / 'RUN.md').write_text(instructions, encoding='utf-8')
    print(f'Initialized {out}. Repository candidates discovered. No deployment inspection or model investigation has run.\nGive RUN.md to your coding agent.')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--repo', action='append', required=True, help='Repeat for multiple repositories; optional ID=/path')
    init.add_argument('--out', required=True); init.add_argument('--name', required=True)
    init.add_argument('--environment', action='append')
    scan = sub.add_parser('discover'); scan.add_argument('--repo', action='append', required=True)
    scan.add_argument('--out', required=True)
    for name in ['validate', 'render', 'questions', 'answer']:
        q = sub.add_parser(name); q.add_argument('report')
        q.add_argument('--repo', action='append')
        if name == 'render':
            q.add_argument('--out', required=True); q.add_argument('--format', choices=['html', 'md'], default='html')
        if name == 'answer':
            q.add_argument('--id', required=True); q.add_argument('--text', required=True)
    ev = sub.add_parser('evidence')
    for key in ['root', 'path', 'id']:
        ev.add_argument('--' + key, required=True)
    ev.add_argument('--root-id', default='repo1')
    ev.add_argument('--start', type=int, required=True); ev.add_argument('--end', type=int, required=True)
    ev.add_argument('--kind', choices=['source', 'deployment', 'attestation'], default='source')
    ev.add_argument('--provenance', default=''); ev.add_argument('--captured-at')
    args = p.parse_args(argv)
    try:
        if args.command == 'evidence':
            print(json.dumps(evidence_record(args.root, args.path, args.start, args.end, args.id, args.root_id, args.kind, args.provenance, args.captured_at), indent=2)); return 0
        roots = roots_from_args(args.repo)
        if args.command == 'init':
            initialize(args, roots); return 0
        if args.command == 'discover':
            with Path(args.out).open('x', encoding='utf-8') as f:
                json.dump(discover(roots), f, indent=2)
            return 0
        report = read_json(args.report)
        if not roots:
            workspace = read_json(Path(args.report).parent / 'workspace.json')
            roots = {k: Path(v).resolve(strict=True) for k, v in workspace['repositories'].items()}
        if args.command in {'questions', 'answer'}:
            for question in report['questions']:
                if args.command == 'answer' and question['id'] == args.id:
                    question.update(answer=args.text, status='answered')
                    write_json(args.report, report)
                    print('Answer recorded as an operator statement. Agent reconciliation and evidence are still required.'); return 0
                if args.command == 'questions' and question['status'] != 'resolved':
                    print(f'{question["id"]} [{question["status"]}]: {question["question"]}\n  Needed: {question["needed_evidence"]}\n  Answer: {question["answer"]}')
                    if question.get('human_blocker'):
                        print('  Human request: ' + json.dumps(question['human_blocker'], ensure_ascii=False))
            if args.command == 'answer':
                raise ReportError('Unknown question ID')
            return 0
        errors = validate(report, args.report, roots)
        if errors:
            print('\n'.join(errors), file=sys.stderr); return 1
        if args.command == 'render':
            with Path(args.out).open('x', encoding='utf-8') as f:
                f.write(render_html(report) if args.format == 'html' else render(report))
        state = delivery_state(report)
        print('Waiting for specific human input.' if state['status'] == 'awaiting_human' else 'Review complete within the declared scope.')
        print('Report evidence and structure checked. Conclusions remain limited to the reviewed model and snapshot.')
        return 0
    except (OSError, ValueError, KeyError, UnicodeError) as exc:
        print(f'Error: {exc}', file=sys.stderr); return 2


if __name__ == '__main__':
    sys.exit(main())
