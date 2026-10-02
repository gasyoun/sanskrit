#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H5544 server canary: HtmlTableFromAlignment must not emit raw user text as markup."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import display
import transliteration.transliterate as T

PAYLOAD = '<img src=x onerror=alert(1)>'

# Identity stub: bypass the real SLP1 transliteration (which would mangle ASCII),
# proving html.escape is the load-bearing defence for payload-bearing syllables.
T.TransliterateForTable = lambda text: text

# Case 1: matching syllables (plain span branch)
alignment_ok = [[(PAYLOAD, 'G', 'G')]]
out1 = '\n'.join(display.HtmlTableFromAlignment(alignment_ok))
# Case 2: mismatching syllables (abbr branch: payload in title AND body)
alignment_bad = [[(PAYLOAD, 'G', PAYLOAD)]]
out2 = '\n'.join(display.HtmlTableFromAlignment(alignment_bad))

fails = []
for name, out in (('plain', out1), ('abbr', out2)):
    if '<img' in out or '<script' in out or '<svg' in out:
        fails.append('%s: raw markup survived: %r' % (name, out))
    if '&lt;img' not in out:
        fails.append('%s: payload not escaped: %r' % (name, out))

# Round-trip: escaping must be faithful (clean data unchanged)
clean = display.HtmlTableFromAlignment([[('ka', 'G', 'G'), ('ti', 'L', 'G')]])
joined = '\n'.join(clean)
expected = '<span class="sylG">ka</span><span class="sylL"><abbr title="Should be G">ti</abbr></span> <br/>\n'
if joined != expected:
    fails.append('clean-data shape changed: %r' % joined)

if fails:
    print('CANARY FAIL')
    [print(' -', f) for f in fails]
    sys.exit(1)
print('SERVER CANARY PASS: payload escaped in both branches, clean-data shape unchanged')
print('--- plain-branch sample:', out1.strip())
print('--- abbr-branch sample:', out2.strip())
