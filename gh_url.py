#!/usr/bin/env python3
import sys, json
try:
    d = json.load(sys.stdin)
    for a in d.get('assets', []):
        if a['name'].endswith('.zip') and 'PUBLIC' in a['name']:
            print(a['browser_download_url']); sys.exit(0)
except Exception as e:
    print('ERR ' + str(e), file=sys.stderr)
sys.exit(1)
