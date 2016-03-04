KAT_URL = 'http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip'
KAT_FILE = 'KAT_AES.zip'

MODES = 'ECB', 'CBC', 'OFB', 'CFB1', 'CFB8', 'CFB128'
TESTS = 'GFSbox', 'KeySbox', 'VarKey', 'VarTxt'
SIZES = '128', '192', '256'

CXX_HEADER = """\
#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

"""

CXX_TEST = """\
TEST_CASE("%(mode)s%(test)s%(size)s-%(sec)s-%(COUNT)s", "%(tags)s") {
"""

CXX_DATA = """\
    const uint8_t %s[] = { %s };
"""

CXX_ENCRYPT = """\
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_encrypt(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
    aes_finish(&state);
}

"""

CXX_DECRYPT = """\
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_begin(&state, KEY, 8 * sizeof KEY));
    REQUIRE(aes_decrypt(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
    aes_finish(&state);
}

"""

import os
import re
import sys
import urllib
import zipfile

try:
    import ConfigParser as configparser
except ImportError:
    import configparser
    unicode = str
    xrange = range

re_blank = re.compile('^ *(#.*)?$')
re_section = re.compile('^\[([^]]+)\]')
re_variable = re.compile('^([A-Za-z0-9_]+) = (.+)$')
re_continue = re.compile('^ +([^ ].*)$')

if not os.path.isfile(KAT_FILE):
    print('Downloading "%s"...' % KAT_FILE)
    filename, headers = urllib.urlretrieve(KAT_URL, KAT_FILE)

zf = zipfile.ZipFile(KAT_FILE)

if zf.testzip() is not None:
    print('Downloaded ZIP is corrupt; delete "%s" and try again.' % KAT_FILE)
    sys.exit()

if not os.path.isdir('tests'):
    os.makedirs('tests')

names = zf.namelist()

found = []
notfound = []
remain = []

def hexformat(s):
    s = [s[i:i+2] for i in xrange(0, len(s), 2)]
    return ','.join('0x%s' % t for t in s)

for mode in MODES:
    for test in TESTS:
        for size in SIZES:
            name = mode+test+size+'.rsp'

            if name in names:
                found.append(name)
                zi = zf.open(name)

                sec = None
                var = None
                vals = {}

                tests = []

                for line in zi:
                    line = unicode(line, 'utf-8').rstrip('\r\n')

                    if re_blank.match(line):
                        if sec and 'COUNT' in vals:
                            vals.update(locals())

                            t = CXX_TEST % vals
                            for k in 'KEY', 'IV', 'PLAINTEXT', 'CIPHERTEXT':
                                if k in vals:
                                    t += CXX_DATA % (k, hexformat(vals[k]))

                            if sec == 'ENCRYPT':
                                tests.append(t + CXX_ENCRYPT)
                            elif sec == 'DECRYPT':
                                tests.append(t + CXX_DECRYPT)
                            else:
                                print('*** Unknown section "%s"' % sec)

                            vals = {}
                            var = None

                    else:
                        m = re_section.match(line)

                        if m:
                            sec = m.group(1)
                            var = None
                            tags = ''.join('[%s]' % s for s in (mode, test, size, sec))
                            continue

                        m = re_variable.match(line)

                        if sec and m:
                            var = m.group(1)
                            vals[var] = m.group(2)
                            continue

                        m = re_continue.match(line)

                        if sec and var and m:
                            vals[var] += m.group(1)
                            continue

                if tests:
                    open('tests/'+mode+test+size+'.cpp','wt').write(CXX_HEADER + ''.join(tests))

            else:
                notfound.append(name)

            names.remove(name)

print('%d test modules generated' % len(found))
print('Tests not found: %s' % (', '.join(notfound) or 'None'))
print('Extra files: %s' % (', '.join(names) or 'None'))
