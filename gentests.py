################################################################################
#
################################################################################

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

extern std::string buf2str(const uint8_t *buf, size_t len);

"""

CXX_TEST = """\
TEST_CASE("%(mode)s%(test)s%(size)s-%(sec)s-%(COUNT)s", "%(tags)s") {
    aes_state state;
"""

CXX_DATA = """\
    const uint8_t %s[] = { %s };
"""

CXX_INIT = """\
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    REQUIRE(aes_init(&state, KEY, AES_KEY_SIZE_%(key_size)d));
"""

CXX_INIT_IV = """\
    CAPTURE(buf2str(KEY, sizeof(KEY)));
    CAPTURE(buf2str(IV, sizeof(IV)));
    REQUIRE(aes_init_iv(&state, KEY, AES_KEY_SIZE_%(key_size)d, IV));
"""

CXX_ENCRYPT = """\
    uint8_t RESULT[sizeof(CIPHERTEXT)];
    CAPTURE(buf2str(PLAINTEXT, sizeof(PLAINTEXT)));
    REQUIRE(aes_encrypt_%(mode)s(&state, PLAINTEXT, RESULT, sizeof(PLAINTEXT)) == sizeof(CIPHERTEXT));
"""

CXX_ENCRYPT_MCT = """\
    for (size_t i = 0; i < 999; ++i) aes_encrypt_%(mode)s(&state, RESULT, RESULT, sizeof(RESULT));
"""

CXX_ENCRYPT_END = """\
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    CAPTURE(buf2str(RESULT, sizeof(RESULT)));
    REQUIRE(memcmp(CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == 0);
}

"""

CXX_DECRYPT = """\
    uint8_t RESULT[sizeof(PLAINTEXT)];
    CAPTURE(buf2str(CIPHERTEXT, sizeof(CIPHERTEXT)));
    REQUIRE(aes_decrypt_%(mode)s(&state, CIPHERTEXT, RESULT, sizeof(CIPHERTEXT)) == sizeof(PLAINTEXT));
"""

CXX_DECRYPT_MCT = """\
    for (size_t i = 0; i < 999; ++i) aes_decrypt_%(mode)s(&state, RESULT, RESULT, sizeof(RESULT));
"""

CXX_DECRYPT_END = """\
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

################################################################################

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

################################################################################

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

                    src = CXX_TEST % vals
                    for k in 'KEY', 'IV', 'PLAINTEXT', 'CIPHERTEXT':
                        if k in vals:
                            src += CXX_DATA % (k, hexformat(vals[k]))

                    init = CXX_INIT_IV if 'IV' in vals else CXX_INIT
                    src += init % { 'key_size': len(vals['KEY'] * 4) }

                    if sec == 'ENCRYPT':
                        src += CXX_ENCRYPT % { 'mode': mode.lower() }
                        if test == 'MCT':
                            src += CXX_ENCRYPT_MCT % { 'mode': mode.lower() }
                        src += CXX_ENCRYPT_END
                    elif sec == 'DECRYPT':
                        src += CXX_DECRYPT % { 'mode': mode.lower() }
                        if test == 'MCT':
                            src += CXX_DECRYPT_MCT % { 'mode': mode.lower() }
                        src += CXX_DECRYPT_END
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

################################################################################

print('%d test modules generated' % len(found))
print('Tests not found: %s' % (', '.join(notfound) or 'None'))
print('Extra files: %s' % (', '.join(names) or 'None'))

################################################################################
# EOF
################################################################################

