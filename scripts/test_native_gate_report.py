"""Reject report paths that could falsely satisfy native operational gates."""

import unittest

from native_gate_report import completed_tests


class NativeExecutionEvidence(unittest.TestCase):
    listing = 'first: test\nsecond: test\n'
    passing = ('test first ... ok\ntest second ... ok\n'
               'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n')

    def test_complete_native_execution(self):
        self.assertEqual(completed_tests(self.listing, self.passing), ['first', 'second'])

    def test_missing_execution(self):
        with self.assertRaises(RuntimeError):
            completed_tests(self.listing, self.passing.replace('test second ... ok\n', ''))

    def test_duplicate_execution(self):
        with self.assertRaises(RuntimeError):
            completed_tests(self.listing, self.passing + 'test first ... ok\n')

    def test_skipped_or_failed_execution(self):
        for state in ['ignored', 'FAILED']:
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                completed_tests(self.listing, self.passing.replace('second ... ok', 'second ... ' + state))

    def test_missing_completion(self):
        with self.assertRaises(RuntimeError):
            completed_tests(self.listing, self.passing.split('test result:')[0])

    def test_empty_or_duplicate_inventory(self):
        for listing in ['', self.listing + 'first: test\n']:
            with self.subTest(listing=listing), self.assertRaises(RuntimeError):
                completed_tests(listing, self.passing)


if __name__ == '__main__':
    unittest.main()
