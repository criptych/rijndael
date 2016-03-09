# Known-Answer Test
KAT_URL = 'http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip'
KAT_FILE = 'KAT_AES.zip'

# Monte Carlo Test
MCT_URL = 'http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmct.zip'
MCT_FILE = 'aesmct.zip'

# Multiblock Message Test
MMT_URL = 'http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip'
MMT_FILE = 'aesmmt.zip'

MODES = 'ECB', 'CBC', 'OFB', 'CFB128', 'CFB8'
TESTS = 'GFSbox', 'KeySbox', 'VarKey', 'VarTxt', 'MCT', 'MMT'
SIZES = '128', '192', '256'

CXX_HEADER = """\
#include "rijndael.h"
#include "catch.hpp"
#include <cstring>

static inline std::string buf2str(const uint8_t *buf, size_t len) {
    std::ostringstream ss; ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(buf[i]) << ' ';
    }
    return ss.str();
}

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
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    REQUIRE(aes_encrypt_%(mode)s(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

"""

CXX_ENCRYPT_MCT = """\
    aes_state state;
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    REQUIRE(aes_encrypt_%(mode)s(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
    for (size_t i = 0; i < 999; ++i) aes_encrypt_%(mode)s(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

"""

CXX_DECRYPT = """\
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    REQUIRE(aes_decrypt_%(mode)s(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

"""

CXX_DECRYPT_MCT = """\
    aes_state state;
    uint8_t RESULT[sizeof(PLAINTEXT)];
    REQUIRE(aes_init_iv(&state, KEY, 8 * sizeof KEY, IV));
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    REQUIRE(aes_decrypt_%(mode)s(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
    for (size_t i = 0; i < 999; ++i) aes_decrypt_%(mode)s(&state, RESULT, RESULT, sizeof(RESULT));
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == 0);
}

"""

import os
import re
import sys
import zipfile

try:
    from urllib import urlretrieve
except ImportError:
    from urllib.request import urlretrieve
    unicode = str
    xrange = range

re_blank = re.compile('^ *(#.*)?$')
re_section = re.compile('^\[([^]]+)\]')
re_variable = re.compile('^([A-Za-z0-9_]+) = (.+)$')
re_continue = re.compile('^ +([^ ].*)$')

def get_test_file(url, fn):
    if not os.path.isfile(fn):
        print('Downloading "%s"...' % fn)
        filename, headers = urlretrieve(url, fn)

    zf = zipfile.ZipFile(fn)

    if zf.testzip() is not None:
        print('Downloaded ZIP "%s" is corrupt.' % fn)
        zf = None

    return zf

kat = get_test_file(KAT_URL, KAT_FILE)
mct = get_test_file(MCT_URL, MCT_FILE)
mmt = get_test_file(MMT_URL, MMT_FILE)

if not os.path.isdir('tests'):
    os.makedirs('tests')

names = {}
names.update({name: kat for name in kat.namelist()})
names.update({name: mct for name in mct.namelist()})
names.update({name: mmt for name in mmt.namelist()})

search = [(mode, test, size) for mode in MODES for test in TESTS for size in SIZES]
notfound = []
found = []

tests = {}

def hexformat(s):
    s = [s[i:i+2] for i in xrange(0, len(s), 2)]
    return ','.join('0x%s' % t for t in s)

for mode, test, size in search:
    name = mode+test+size+'.rsp'

    if name in names:
        found.append(name)
        zi = names[name].open(name)

        sec = None
        var = None
        vals = {}

        for line in zi:
            line = unicode(line, 'utf-8').rstrip('\r\n')

            if re_blank.match(line):
                if sec and 'COUNT' in vals:
                    vals.update(locals())

                    if 'IV' not in vals:
                        vals['IV'] = '00'*16

                    t = CXX_TEST % vals
                    for k in 'KEY', 'IV', 'PLAINTEXT', 'CIPHERTEXT':
                        if k in vals:
                            t += CXX_DATA % (k, hexformat(vals[k]))

                    if sec == 'ENCRYPT':
                        if test == 'MCT':
                            src = (t + CXX_ENCRYPT_MCT % { 'mode': mode.lower() })
                        else:
                            src = (t + CXX_ENCRYPT % { 'mode': mode.lower() })
                    elif sec == 'DECRYPT':
                        if test == 'MCT':
                            src = (t + CXX_DECRYPT_MCT % { 'mode': mode.lower() })
                        else:
                            src = (t + CXX_DECRYPT % { 'mode': mode.lower() })
                    else:
                        print('*** Unknown section "%s"' % sec)

                    tests.setdefault(mode, []).append(src)

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

    else:
        notfound.append(name)

    del names[name]

for k, v in sorted(tests.items()):
    open('tests/' + k.lower() + 'tests.cpp', 'wt').write(CXX_HEADER + ''.join(v))

print('%d test modules generated' % len(found))
print('Tests not found: %s' % (', '.join(notfound) or 'None'))
print('Extra files: %s' % (', '.join(names) or 'None'))

