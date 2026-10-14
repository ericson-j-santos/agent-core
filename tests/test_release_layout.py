"""Verify the candidate contains only generic code and enforceable rule templates."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReleaseContract(unittest.TestCase):
    def test_publication_ruleset_is_scoped(self):
        policy = json.loads((ROOT / '.github/rulesets/agent-core-main.json').read_text())
        self.assertEqual(policy['target'], 'branch')
        self.assertEqual(policy['enforcement'], 'active')
        self.assertEqual(policy['conditions']['ref_name']['include'], ['refs/heads/main'])
        self.assertEqual(policy['bypass_actors'], [])
        self.assertIn('required_status_checks', [r['type'] for r in policy['rules']])
        required = next(r for r in policy['rules'] if r['type'] == 'required_status_checks')
        self.assertEqual(required['parameters']['required_status_checks'], [{'context':'agent-core-test'}])
        self.assertTrue(required['parameters']['strict_required_status_checks_policy'])
        self.assertEqual(next(r for r in policy['rules'] if r['type']=='pull_request')['parameters']['required_approving_review_count'], 0)

    def test_release_contains_no_private_project_names(self):
        for path in ROOT.rglob('*'):
            if not path.is_file() or '.git' in path.parts or '__pycache__' in path.parts:
                continue
            if path.suffix not in {'.py', '.md', '.toml', '.yml', '.json'}:
                continue
            text = path.read_text(encoding='utf-8')
            for forbidden in ('reqsys'+'-v2-enterprise-real', 'reqsys'+'-engineering-orchestrator',
                              'ericson'+'-j-santos', 'DESKTOP'+'-PDQK954',
                              'noteri'+'-runtime', 'github'+'_pat_', 'gh'+'p_'):
                self.assertNotIn(forbidden, text, (path, forbidden))

    def test_workflow_read_only_and_check_named(self):
        text=(ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('name: agent-core-test', text)
        self.assertIn('pull_request:', text)
        self.assertIn('permissions:', text)
        self.assertNotIn('issues: write', text)
        self.assertNotIn('contents: write', text)
        self.assertIn('github_negative_control_missing', text)
        self.assertIn("observed.get('state_changed') is not False", text)
