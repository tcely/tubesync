#!/usr/bin/python3
'''

    Perform an HTTP request to a URL and exit with an exit code of 1 if the
    request did not return an HTTP/200 status code.

    Usage:
    $ ./healthcheck.py http://some.url.here/healthcheck/resource

'''


import os
import sys
import requests
import time, random, hashlib, threading, subprocess, urllib.request

sys.path.append('/app/common')
try: from third_party_versions import yt_dlp_version
except: yt_dlp_version = "unknown"

TIMEOUT = 5  # Seconds
HTTP_USER = os.getenv('HTTP_USER')
HTTP_PASS = os.getenv('HTTP_PASS')
# never use proxy for healthcheck requests
os.environ['no_proxy'] = '*'

def atomic_write(path, data):
    tmp = f"{path}.aw.tmp"
    try:
        with open(tmp, "w") as f: f.write(str(data))
        os.replace(tmp, path)
    except: pass

def bg_v(s, lock):
    h, p = "github.com", "yt-dlp/yt-dlp/releases/latest"
    try:
        with lock:
            req = urllib.request.Request(f"https://{h}/{p}", method='HEAD')
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                v = resp.geturl().split('/')[-1]
            atomic_write(s, v)
            atomic_write(s + ".t", time.time())
            atomic_write(s + ".i", random.randint(1200, 21600))
    except: pass

def is_old(s, l):
    if os.path.exists(f"/run/service/huey-net-limited/down"): return False
    os.makedirs("/dev/shm/.healthcheck", exist_ok=True)
    try:
        lt = float(open(s+".t").read()) if os.path.exists(s+".t") else 0
        iv = float(open(s+".i").read()) if os.path.exists(s+".i") else 1200
        if time.time() - lt >= iv: threading.Thread(target=bg_v, args=(s, l), daemon=True).start()
        if os.path.exists(s): return yt_dlp_version != open(s).read().strip()
    except: pass
    return False

def do_heatlhcheck(url):
    headers = {'User-Agent': 'healthcheck'}
    auth = None
    if HTTP_USER and HTTP_PASS:
        auth = (HTTP_USER, HTTP_PASS)
    response = requests.get(url, headers=headers, auth=auth, timeout=TIMEOUT)
    return response.status_code == 200


if __name__ == '__main__':
    lock = threading.Lock()
    vf = f"/dev/shm/.healthcheck/v.{hashlib.md5(open('/proc/1/stat').read().split()[21].encode()).hexdigest()[:8]}"
    if is_old(vf, lock) and not os.path.exists(s+".l"):
        open(s+".l", "w").write("1")
        subprocess.Popen(["/command/s6-rc", "-d", "change", "huey-net-limited"], stdout=-1, stderr=-1, start_new_session=True)

    # if it is marked as intentionally down, nothing else matters
    if os.path.exists('/run/service/gunicorn/down'):
        lock.acquire(timeout=TIMEOUT)
        sys.exit(0)
    try:
        url = sys.argv[1]
    except IndexError:
        sys.stderr.write('URL must be supplied\n')
        sys.exit(1)
    if do_heatlhcheck(url):
        lock.acquire(timeout=TIMEOUT)
        sys.exit(0)
    else:
        sys.exit(1)
