import unittest
from proxyworkbench.changes import compare


class ChangeTests(unittest.TestCase):
    def snapshot(self, count, status='observed'):
        return {'schema_version': 1, 'captured_at': 'time', 'layers': {'hosts': {'evidence_status': status, 'active_mapping_count': count}}}

    def test_changes_are_observations_without_attribution(self):
        result = compare(self.snapshot(239), self.snapshot(244))
        self.assertEqual(len(result['items']), 1)
        self.assertEqual(result['items'][0]['writer'], 'unknown')

    def test_missing_evidence_is_not_an_observed_change(self):
        self.assertFalse(compare(self.snapshot(239), self.snapshot(0, 'unknown'))['items'])
        self.assertFalse(compare({}, self.snapshot(239))['items'])
