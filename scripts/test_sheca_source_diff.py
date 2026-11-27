import json
import unittest

from sheca_source_adapter import SECTIONS, digest
from sheca_source_diff import compare
from test_sheca_source_adapter import table, wrap


def page(root=None, intermediate=None, disuse=None):
    h = list(SECTIONS)
    root = [('Root', 'a'*40)] if root is None else root
    intermediate = [('Intermediate', 'b'*40)] if intermediate is None else intermediate
    disuse = [('Old', 'c'*40)] if disuse is None else disuse
    return table(h[0], root) + table(h[1], intermediate) + table(h[2], disuse)


def capture(html, at='2026-11-27T00:00:00Z', mode='LOCAL_INPUT'):
    data, _ = wrap(html)
    o = json.loads(data)
    o['recordedAt'] = at
    o['mode'] = mode
    if mode == 'HTTPS_RESPONSE':
        o['mediaType'] = 'text/html'
    data = json.dumps(o).encode()
    return data, digest(data)


def diff(a, b):
    return compare(*capture(a), *capture(b, '2026-11-28T00:00:00Z'))


class SemanticDiffTest(unittest.TestCase):
    def test_formatting_only(self):
        a = page()
        r = diff(a, '<div class="layout">' + a + '</div>')
        self.assertEqual(r['status'], 'BODY_CHANGED_PROJECTED_ROWS_UNCHANGED')
        self.assertFalse(r['reviewSuggested'])
        self.assertEqual(r['changes'], [])
        self.assertEqual(diff(a, a)['status'], 'BODY_AND_PROJECTED_ROWS_UNCHANGED')

    def test_new_and_missing_are_claims_not_certificates(self):
        r = diff(page(), page(root=[('Root', 'd'*40)]))
        self.assertEqual(r['counts']['newFingerprintClaims'], 1)
        self.assertEqual(r['counts']['missingFingerprintClaims'], 1)
        self.assertEqual({x['kind'] for x in r['changes']}, {
            'NEW_PUBLISHED_FINGERPRINT_CLAIM', 'PUBLISHED_FINGERPRINT_NOT_OBSERVED'})
        self.assertEqual(r['certificateIdentity'], 'NOT_ESTABLISHED')
        self.assertEqual(r['trustStatus'], 'NOT_ESTABLISHED')

    def test_section_and_fields(self):
        a = page(intermediate=[('Intermediate', 'b'*40), ('Other', 'd'*40)])
        b = page(intermediate=[('Other', 'd'*40)], disuse=[('Old', 'c'*40), ('Renamed', 'b'*40)])
        b = b.replace('December 31, 2036', 'January 1, 2037').replace('/test.pem', '/next.pem')
        r = diff(a, b)
        change = next(x for x in r['changes'] if x['publishedSHA1'] == 'b'*40)
        self.assertEqual(change['kind'], 'SINGLE_CLAIM_FIELDS_CHANGED')
        self.assertEqual(change['changedFields'], ['section', 'label', 'publishedValidUntil', 'observedHrefs'])
        self.assertEqual(r['counts']['missingFingerprintClaims'], 0)

    def test_ambiguous_group_and_duplicate_count(self):
        a = page(root=[('Root', 'a'*40), ('Alias', 'a'*40)])
        b = page(root=[('Root', 'a'*40), ('Other Alias', 'a'*40)])
        r = diff(a, b)
        self.assertEqual(r['changes'][0]['kind'], 'AMBIGUOUS_FINGERPRINT_GROUP_CHANGED')
        self.assertEqual(r['changes'][0]['changedFields'], [])
        self.assertTrue(diff(a, a)['reviewSuggested'])
        r = diff(page(), page(root=[('Root', 'a'*40), ('Root', 'A'*40)]))
        self.assertEqual(r['status'], 'EXACT_DUPLICATE_COUNT_CHANGED_REVIEW_REQUIRED')
        self.assertTrue(r['reviewSuggested'])
        self.assertEqual(r['changes'], [])

    def test_reorder_deterministic(self):
        a = page(root=[('Root', 'a'*40), ('Other', 'd'*40)])
        b = page(root=[('Other', 'd'*40), ('Root', 'a'*40)])
        self.assertEqual(diff(a, b)['changes'], [])
        self.assertEqual(diff(a, b), diff(a, b))

    def test_pins_time_mode_and_bad_page(self):
        a = capture(page())
        b = capture(page(), '2026-11-27T00:00:00.000000001Z')
        self.assertEqual(compare(*a, *b)['changes'], [])
        with self.assertRaises(ValueError): compare(*b, *a)
        with self.assertRaises(ValueError): compare(*a, *a)
        with self.assertRaises(ValueError): compare(*a, b[0], '0'*64)
        with self.assertRaises(ValueError): compare(*a, *capture(page(), '2026-11-28T00:00:00Z', 'HTTPS_RESPONSE'))
        with self.assertRaises(ValueError): diff(page(), '<html>challenge</html>')


if __name__ == '__main__':
    unittest.main()
