import base64
import json
import unittest
from sheca_source_adapter import SOURCE, SECTIONS, HEADER, digest, project


def table(heading, rows):
    return '<h3>' + heading + '</h3><table><tr>' + ''.join('<th>'+x+'</th>' for x in HEADER) + '</tr>' + ''.join('<tr><td>'+name+'</td><td>'+sha+'</td><td>December 31, 2036</td><td><a href="/test.pem">PEM</a></td></tr>' for name,sha in rows) + '</table>'


def fixture():
    headings = list(SECTIONS)
    return table(headings[0], [('Example Root','AA:'*19+'AA')]) + table(headings[1], [('Example Intermediate','b'*40), ('Example Intermediate','c'*40)]) + table(headings[2], [('Example Old','d'*40), ('Example Old','D'*40), ('Example Alias','d'*40)])


def wrap(html):
    body=html.encode()
    o=dict(schemaVersion='1',source=SOURCE,recordedAt='2026-11-27T00:00:00Z',mode='LOCAL_INPUT',bodySHA256=digest(body),bodyBytes=len(body),raw=base64.b64encode(body).decode(),sourceAuthentication='NOT_ESTABLISHED',trustStatus='NOT_ESTABLISHED')
    raw=json.dumps(o).encode()
    return raw,digest(raw)


class AdapterTest(unittest.TestCase):
    def test_projection(self):
        raw,pin=wrap(fixture())
        r=project(raw,pin)
        self.assertEqual(len(r['rows']),5)
        self.assertEqual(r['exactDuplicateRows'],1)
        self.assertEqual(r['repeatedPublishedSHA1'],['d'*40])
        self.assertEqual(r['trustStatus'],'NOT_ESTABLISHED')
        self.assertEqual(r,project(raw,pin))

    def test_wrong_pin(self):
        raw,pin=wrap(fixture())
        with self.assertRaises(ValueError): project(raw,'0'*64)

    def test_bad_html(self):
        for bad in [fixture().replace('December 31, 2036','December 32, 2036'),fixture().replace('Fingerprint / 指纹（SHA1）','SHA256'),fixture().replace('Disuse Certificates / 停用证书','Other'),fixture().replace('href="/test.pem"',''),fixture().replace('b'*40,'b'*39),fixture()+'<table>', '<html>challenge</html>']:
            with self.subTest(bad=bad[:70]),self.assertRaises(ValueError): project(*wrap(bad))

    def test_script_and_reorder(self):
        raw,pin=wrap('<script>'+fixture()+'</script>'+fixture())
        r=project(raw,pin)
        self.assertEqual(len(r['rows']),5)


    def test_nested_ignored_elements(self):
        expected = project(*wrap(fixture()))["rows"]
        hidden = "<template><template>nested</template>" + fixture() + "</template>"
        self.assertEqual(project(*wrap(hidden + fixture()))["rows"], expected)
        hidden = "<template><noscript>" + fixture() + "</noscript></template>"
        self.assertEqual(project(*wrap(hidden + fixture()))["rows"], expected)
        for bad in ("<template><template></template>" + fixture(),
                    "<template><noscript></template></noscript>" + fixture(),
                    "<template>"*33 + "</template>"*33 + fixture()):
            with self.assertRaises(ValueError):
                project(*wrap(bad))


if __name__=='__main__': unittest.main()
