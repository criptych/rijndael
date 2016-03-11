################################################################################
#
################################################################################

CHECK = unichr(0x2713)
CROSS = unichr(0x2717)

STAT_HEADER = """\
### NIST CAVP Test Result Status

| Mode     | Test    | Encrypt: 128-bit | 192-bit | 256-bit | Decrypt: 128-bit | 192-bit | 256-bit |
| -------- | ------- | ---------------: | ------: | ------: | ---------------: | ------: | ------: |
"""

STAT_ITEM = """\
| %-8s | %-7s | %6s | %6s | %6s | %6s | %6s | %6s |
"""

STAT_NOTES = """\

> *Note: Support for CFB-1 mode has been removed.  It provides no significant
> benefit in return for the added complexity to implement it and the 128x
> slowdown compared to CFB-128.

[%s]: check16.png
[%s]: cross16.png

""" % (CHECK, CROSS)

MODES = u'ECB', u'CBC', u'OFB', u'CFB128', u'CFB8'
TESTS = u'GFSbox', u'KeySbox', u'VarKey', u'VarTxt', u'MMT', u'MCT'
SIZES = u'128', u'192', u'256'

MODETEXT = {
    u'CFB128': u'CFB-128',
    u'CFB8': u'CFB-8',
    u'CFB1': u'CFB-1*',
}

import argparse
import codecs
import re
from xml.dom.minidom import parse as parseXml, Node

re_tags = re.compile(r'^(%s)(%s)(%s)-((?:EN|DE)CRYPT)-\d+' % (
    '|'.join(MODES), '|'.join(TESTS), '|'.join(SIZES)))

################################################################################

stats = {}

def parseCatchTestCase(tc):
    name = tc.getAttribute('name')
    tags = re_tags.match(name).groups()
    #~ print(tags)

    stat = 0

    for ch in tc.childNodes:
        if (ch.nodeType == Node.ELEMENT_NODE and
            ch.tagName == 'OverallResult' and
            ch.getAttribute('success') == 'true'
        ):
            stat += 1

    tup = stats.get(tags, (0,0))
    stats[tags] = tup[0]+1, tup[1]+stat

def parseCatchGroup(group):
    for ch in group.childNodes:
        if ch.nodeType == Node.ELEMENT_NODE and ch.tagName == 'TestCase':
            parseCatchTestCase(ch)

def parseCatch(root):
    for ch in root.childNodes:
        if ch.nodeType == Node.ELEMENT_NODE and ch.tagName == 'Group':
            parseCatchGroup(ch)

################################################################################

def generate(infn, outfn):
    print('Generating report "%s" from log "%s"' % (outfn, infn))

    results = parseXml(infn)

    parseCatch(results.documentElement)

    def addrow(mode, test, first=False):
        row = [MODETEXT.get(mode, mode) if first else '', test]
        for ed in u'ENCRYPT', u'DECRYPT':
            for size in SIZES:
                try:
                    ntest, npass = stats[mode, test, size, ed]
                    ok = ntest == npass
                except KeyError:
                    ok = False
                finally:
                    d = 'PASS' if ok else 'FAIL'
                    i = CHECK if ok else CROSS
                    row.append('![%s][%s]' % (d, i))
        return row

    with codecs.open(outfn, 'w', encoding='utf-8') as f:
        f.write(STAT_HEADER)

        for mode in MODES:
            first = True
            for test in TESTS:
                row = addrow(mode, test, first)
                f.write(STAT_ITEM % tuple(row))
                first = False

        row = addrow('CFB-1*', '-------', True)
        f.write(STAT_ITEM % tuple(row))

        f.write(STAT_NOTES)

    print('Done.')

################################################################################

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', nargs='?', default='alltests.xml')
    parser.add_argument('outfile', nargs='?', default='status.md')
    options = parser.parse_args()
    generate(options.infile, options.outfile)

################################################################################
# EOF
################################################################################

