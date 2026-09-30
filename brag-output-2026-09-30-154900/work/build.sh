#!/usr/bin/env bash
# Build work/frame.html from the template + real parser output.
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$D" <<'PY'
import json, sys
d = sys.argv[1]
data = json.load(open(f'{d}/work/data.json'))
tpl = open(f'{d}/work/frame.tpl.html').read()
out = tpl.replace('__DATA__', json.dumps(data, separators=(',', ':')))
assert '__DATA__' not in out, 'data not injected'
open(f'{d}/work/frame.html', 'w').write(out)
print('built work/frame.html')
PY
