import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import boundary_map as bm
EXAMPLE = ROOT / 'examples/fictional-payments'
REPORT = EXAMPLE / 'report.json'


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.report = bm.read_json(REPORT)

    def errors(self):
        return bm.validate(self.report, REPORT, {'repo1': EXAMPLE})

    def result(self, scenario='S_runtime', boundary='B_payout'):
        s = next(s for s in self.report['scenarios'] if s['id'] == scenario)
        return next(x for x in bm.assess(self.report, s)['results'] if x['boundary_id'] == boundary)

    def test_example_valid_and_outputs_current(self):
        self.assertEqual([], self.errors())
        self.assertEqual((EXAMPLE / 'REPORT.md').read_text(), bm.render(self.report))
        self.assertEqual((EXAMPLE / 'map.html').read_text(), bm.render_html(self.report))

    def test_runtime_has_three_distinct_outcomes(self):
        self.assertEqual('survives', self.result()['status'])
        self.assertEqual('defeated', self.result(boundary='B_dest')['status'])
        self.assertEqual('unverified', self.result(boundary='B_refund')['status'])

    def test_pending_result_has_exact_human_request(self):
        state = bm.delivery_state(self.report)
        self.assertEqual('awaiting_human', state['status'])
        result = next(a for a in state['assessments'] if a['id'] == 'S_runtime')
        refund = next(r for r in result['results'] if r['boundary_id'] == 'B_refund')
        self.assertEqual(['Q_refund'], [q['question_id'] for q in refund['human_requests']])
        self.assertIn('read-only', refund['human_requests'][0]['request'])
        output = bm.render(self.report)
        self.assertIn('Waiting for your input', output)
        self.assertIn('Exact input needed to finish', output)

    def test_generic_unknown_cannot_be_delivered_in_either_format(self):
        del self.report['questions'][0]['human_blocker']
        self.assertTrue(any('Agent work remains' in e for e in self.errors()))
        for renderer in [bm.render, bm.render_html]:
            with self.subTest(renderer=renderer.__name__), self.assertRaises(bm.ReportError):
                renderer(self.report)

    def test_request_cannot_hide_unrelated_missing_ownership(self):
        next(n for n in self.report['nodes'] if n['id'] == 'customer_key')['owner_ids'] = []
        self.assertIn('owner:customer_key', '\n'.join(self.errors()))
        self.assertEqual('unverified', self.result()['status'])

    def test_request_must_cover_every_dependent_gap(self):
        self.report['questions'][0]['human_blocker']['gap_ids'].remove('edge:refund_unknown')
        self.assertIn('Agent work remains [edge:refund_unknown]', '\n'.join(self.errors()))

    def test_request_needs_actual_attempts_and_named_human(self):
        h = self.report['questions'][0]['human_blocker']
        h['attempted_checks'] = []
        h['requested_from'] = ''
        errors = '\n'.join(self.errors())
        self.assertIn('attempted_checks', errors)
        self.assertIn('requested_from', errors)

    def test_request_timestamp_requires_timezone(self):
        self.report['questions'][0]['human_blocker']['asked_at'] = '2026-10-25T12:00:00'
        self.assertIn('asked_at', '\n'.join(self.errors()))

    def test_agent_review_cannot_be_waived_by_human_request(self):
        self.report['boundaries'][2]['challenge'] = 'unresolved'
        q = self.report['questions'][0]
        q['human_blocker']['gap_ids'].append('challenge:B_refund')
        self.assertIn('agent work cannot be delegated', '\n'.join(self.errors()))

    def test_answer_returns_work_to_agent_before_delivery(self):
        self.report['questions'][0].update(status='answered', answer='Owner has supplied the provider export.')
        self.assertIn('reconcile it before delivery', '\n'.join(self.errors()))
        self.assertEqual('unverified', self.result(boundary='B_refund')['status'])

    def test_request_must_match_affected_target(self):
        self.report['questions'][0]['affects'].remove('provider')
        self.assertIn('request does not affect target of owner:provider', '\n'.join(self.errors()))

    def test_unknown_enforcer_requires_its_missing_fact_not_false_bypass(self):
        self.report['edges'].append(dict(id='maybe_provider', source='api', target='provider', requires_all=[],
                                        description='Provider admin grant needs inspection', basis='unknown',
                                        relation='administer', evidence_ids=[]))
        q = self.report['questions'][0]
        q['affects'].append('maybe_provider')
        q['human_blocker']['gap_ids'].append('edge:maybe_provider')
        self.assertEqual([], self.errors())
        self.assertEqual('unverified', self.result(boundary='B_refund')['status'])

    def test_completed_investigation_has_no_pending_outcome(self):
        self.report['questions'] = []
        next(n for n in self.report['nodes'] if n['id'] == 'provider')['owner_ids'] = ['company']
        next(e for e in self.report['edges'] if e['id'] == 'refund_unknown').update(basis='observed', evidence_ids=['Elive'])
        self.report['boundaries'][2]['remaining_checks'] = []
        self.report['coverage'][-1]['status'] = 'inspected'
        self.assertEqual([], self.errors())
        self.assertEqual('complete', bm.delivery_state(self.report)['status'])
        self.assertNotIn('unverified', {r['status'] for a in bm.delivery_state(self.report)['assessments'] for r in a['results']})

    def test_defeated_path_does_not_hide_unfinished_investigation(self):
        self.report['scenarios'] = [dict(self.report['scenarios'][0], initial_control=['payout', 'destination', 'refund'])]
        del self.report['questions'][0]['human_blocker']
        self.assertEqual({'defeated'}, {r['status'] for r in bm.assess(self.report, self.report['scenarios'][0])['results']})
        self.assertIn('Agent work remains', '\n'.join(self.errors()))

    def test_deployment_indirectly_exposes_runtime_admin(self):
        self.assertEqual('defeated', self.result('S_employee', 'B_dest')['status'])
        s = next(s for s in self.report['scenarios'] if s['id'] == 'S_employee')
        known, paths = bm.reachable(self.report, s)
        self.assertIn('admin', known)
        self.assertEqual('api_admin', paths['admin'])

    def test_and_approval_does_not_become_or(self):
        s = next(s for s in self.report['scenarios'] if s['id'] == 'S_runtime')
        self.assertNotIn('payout', bm.reachable(self.report, s)[0])
        s['initial_control'].append('customer_key')
        self.assertEqual('defeated', self.result()['status'])

    def test_recovery_or_upgrade_bypass_defeats_signature(self):
        self.assertEqual('defeated', self.result('S_admin')['status'])

    def test_unknown_key_access_prevents_survives(self):
        self.report['edges'].append(dict(id='maybe_key', source='api', target='customer_key', requires_all=[], description='Unknown recovery path', basis='unknown', relation='recover', evidence_ids=[]))
        self.assertEqual('unverified', self.result()['status'])

    def test_source_is_possible_not_deployment_observed(self):
        self.report['edges'].append(dict(id='source_key', source='api', target='customer_key', requires_all=[], description='Source-only grant', basis='source', relation='recover', evidence_ids=['Esource']))
        self.assertEqual('unverified', self.result()['status'])

    def test_cycles_terminate_without_inventing_authority(self):
        self.report['edges'].append(dict(id='cycle', source='ops', target='api', requires_all=[], description='Cycle', basis='observed', relation='other', evidence_ids=['Elive']))
        self.assertEqual('survives', self.result()['status'])

    def test_unknown_owner_affects_dependent_boundary(self):
        n = next(n for n in self.report['nodes'] if n['id'] == 'customer_key')
        n['owner_ids'] = []
        self.assertEqual('unverified', self.result()['status'])
        self.assertEqual('defeated', self.result(boundary='B_dest')['status'])

    def test_answer_alone_does_not_resolve_question(self):
        self.report['questions'].append(dict(id='Q_key', question='Who recovers customer key?', affects=['customer_key'], needed_evidence='Recovery policy', answer='Customer', status='answered', evidence_ids=[]))
        self.assertEqual('unverified', self.result()['status'])
        self.report['questions'][-1]['status'] = 'resolved'
        self.assertTrue(any('corroborating' in e for e in self.errors()))

    def test_incomplete_system_inventory_blocks_survival(self):
        self.report['coverage'][0]['status'] = 'partial'
        self.assertEqual('unverified', self.result()['status'])

    def test_each_action_and_alternative_gate_must_be_accounted_for(self):
        self.report['boundaries'][0]['gate_ids'].pop()
        self.assertTrue(any('every modeled incoming' in e for e in self.errors()))
        self.report['boundaries'].pop()
        self.assertTrue(any('action needs a boundary' in e for e in self.errors()))

    def test_observed_grants_need_live_evidence(self):
        self.report['edges'][0]['evidence_ids'] = ['Esource']
        self.assertTrue(any('deployment evidence' in e for e in self.errors()))
        self.report['evidence'][-1]['kind'] = 'attestation'
        self.assertTrue(any('deployment evidence' in e for e in self.errors()))

    def test_hash_line_range_and_provenance_checks(self):
        self.report['evidence'][0]['sha256'] = '0' * 64
        self.report['evidence'][1]['end_line'] = 99999
        self.assertTrue(any('hash does not match' in e for e in self.errors()))
        self.assertTrue(any('Invalid line range' in e for e in self.errors()))
        self.report = bm.read_json(REPORT)
        self.report['evidence'][1]['provenance'] = ''
        self.assertTrue(any('provenance' in e for e in self.errors()))

    def test_missing_coverage_categories_are_visible(self):
        self.report['coverage'] = [c for c in self.report['coverage'] if c['category'] != 'recovery']
        self.assertTrue(any('missing coverage categories' in e for e in self.errors()))

    def test_duplicate_ids_references_and_schema(self):
        self.report['nodes'][0]['id'] = self.report['scenarios'][0]['id']
        self.report['edges'][0]['target'] = 'unknown'
        errors = self.errors()
        self.assertTrue(any('unique across' in e for e in errors))
        self.assertTrue(any('unknown reference' in e for e in errors))
        del self.report['system']['environments']
        self.assertTrue(any('required' in e for e in self.errors()))

    def test_html_cannot_execute_report_text(self):
        self.report['system']['name'] = '</script><script>alert(1)</script>'
        output = bm.render_html(self.report)
        self.assertNotIn(self.report['system']['name'], output)
        self.assertIn('\\u003c/script', output)
        self.assertNotIn('https://', output)

    def test_untrusted_file_paths_and_secret_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); repo = base / 'repo'; repo.mkdir()
            outside = base / 'outside'; outside.write_text('secret')
            (repo / 'escape').symlink_to(outside)
            (repo / '.env').write_text('SECRET=abc')
            (repo / 'alias').symlink_to(repo / '.env')
            for name in ['../outside', str(outside), 'escape', '.env', 'alias']:
                with self.subTest(name=name), self.assertRaises(bm.ReportError):
                    bm.evidence_record(repo, name, 1, 1, 'E')

    def test_discovery_multiple_repos_skips_secret_values_and_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); a = base / 'a'; b = base / 'b'; a.mkdir(); b.mkdir()
            (a / 'app.ts').write_text('const k = process.env.SIGNING_KEY;')
            (a / '.env.production').write_text('SIGNING_KEY=DO_NOT_READ')
            (b / 'deploy.py').write_text('import os\nx=os.environ["CLOUD_ROLE"]')
            (a / 'alias.ts').symlink_to(a / '.env.production')
            result = bm.discover({'api': a, 'worker': b})
            self.assertEqual(2, len(result['files']))
            self.assertEqual(['SIGNING_KEY'], result['files'][0]['credential_name_candidates'])
            self.assertNotIn('DO_NOT_READ', json.dumps(result))
            limited = bm.discover({'api': a}, max_files=0)
            self.assertIn('incomplete', limited['limitations'][0])


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'boundary_map.py'), *map(str,args)], text=True,capture_output=True,timeout=10)

    def test_init_discovers_system_without_route_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'private'
            args = ['init','--repo',f'api={EXAMPLE}','--name','Test system','--out',out]
            result = self.run_cli(*args)
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertIn('No deployment inspection',result.stdout)
            self.assertNotIn('operation',bm.read_json(out/'report.json')['system'])
            instructions = (out/'RUN.md').read_text()
            self.assertIn('user-question tool',instructions)
            self.assertIn('Inspect actual deployments',instructions)
            self.assertTrue(bm.read_json(out/'discovery.json')['files'])
            self.assertEqual(1,self.run_cli('validate',out/'report.json').returncode)
            self.assertEqual(2,self.run_cli(*args).returncode)

    def test_render_offline_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'map.html'
            args=['render',REPORT,'--repo',f'repo1={EXAMPLE}','--out',output]
            self.assertEqual(0,self.run_cli(*args).returncode)
            self.assertEqual((EXAMPLE/'map.html').read_text(),output.read_text())
            self.assertEqual(2,self.run_cli(*args).returncode)

    def test_cli_will_not_write_a_report_with_agent_work_remaining(self):
        with tempfile.TemporaryDirectory() as folder:
            report = bm.read_json(REPORT)
            del report['questions'][0]['human_blocker']
            path = Path(folder) / 'report.json'; bm.write_json(path, report)
            output = Path(folder) / 'map.html'
            for fmt in ['html', 'md']:
                result = self.run_cli('render', path, '--repo', f'repo1={EXAMPLE}',
                                      '--out', output, '--format', fmt)
                self.assertEqual(1, result.returncode, result.stderr)
                self.assertIn('Agent work remains', result.stderr)
                self.assertFalse(output.exists())

    def test_answer_is_saved_but_not_verified(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'report.json';bm.write_json(path,bm.read_json(REPORT))
            result=self.run_cli('answer',path,'--repo',f'repo1={EXAMPLE}','--id','Q_refund','--text','Provider administrator owns recovery')
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertEqual('answered',bm.read_json(path)['questions'][0]['status'])
            self.assertIn('answered',self.run_cli('questions',path,'--repo',f'repo1={EXAMPLE}').stdout)
            self.assertEqual(2,self.run_cli('answer',path,'--repo',f'repo1={EXAMPLE}','--id','absent','--text','answer').returncode)

    def test_live_evidence_requires_original_capture_time(self):
        result=self.run_cli('evidence','--root',EXAMPLE,'--path','snapshots/deployment.json','--start',1,'--end',3,'--id','E','--kind','deployment')
        self.assertEqual(2,result.returncode)
        self.assertIn('original --captured-at',result.stderr)

    def test_bad_json_useful_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'bad.json';path.write_text('{bad')
            result=self.run_cli('validate',path,'--repo',f'repo1={EXAMPLE}')
            self.assertEqual(2,result.returncode);self.assertIn('Cannot read JSON',result.stderr)


if __name__ == '__main__':
    unittest.main()
