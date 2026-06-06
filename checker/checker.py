import json
import re
import secrets
import string
import sys
import time
from pathlib import Path

import requests


class CheckerResult:
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECK_FAILED = 110


FLAG_RE = re.compile(r"^[A-Z0-9]{31}=$")
STATE_FILE = Path(__file__).with_name("checker_flags.json")
TIMEOUT = 4


def base_url(ip, port):
    return f"http://{ip}:{port}"


def generate_random_flag(length=31):
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length)) + "="


def load_state():
    if not STATE_FILE.exists():
        return []
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return []


def save_state(items):
    STATE_FILE.write_text(json.dumps(items, indent=2, sort_keys=True))


def rnd(prefix):
    return prefix + secrets.token_hex(8)


def register(session, url):
    username = rnd("u_")
    password = rnd("p_") + "Aa1"
    r = session.post(
        f"{url}/api/users/register",
        json={"username": username, "password": password},
        timeout=TIMEOUT,
    )
    if r.status_code not in (200, 201):
        raise ValueError(f"register status {r.status_code}")
    data = r.json()
    token = data.get("token")
    if not token:
        raise ValueError("no token")
    return username, password, token


def create_case(session, url, token, flag):
    headers = {"Authorization": f"Bearer {token}"}
    title = "incident-" + secrets.token_hex(4)
    r = session.post(
        f"{url}/api/cases",
        headers=headers,
        json={
            "title": title,
            "category": "network",
            "public_summary": "Training checker case",
            "secret_note": flag,
        },
        timeout=TIMEOUT,
    )
    if r.status_code not in (200, 201):
        raise ValueError(f"create case status {r.status_code}")
    data = r.json()
    if not isinstance(data.get("case_id"), int):
        raise ValueError("no case_id")
    return data["case_id"], title


def check(target_ip, target_port, *args):
    url = base_url(target_ip, target_port)
    try:
        s = requests.Session()
        h = s.get(f"{url}/health", timeout=TIMEOUT)
        if h.status_code != 200 or h.json().get("status") != "ok":
            return CheckerResult.MUMBLE
        _, _, token = register(s, url)
        probe_flag = generate_random_flag()
        case_id, title = create_case(s, url, token, probe_flag)
        headers = {"Authorization": f"Bearer {token}"}
        g = s.get(f"{url}/api/cases/{case_id}", headers=headers, timeout=TIMEOUT)
        if g.status_code != 200:
            return CheckerResult.CORRUPT
        body = g.json()
        if body.get("secret_note") != probe_flag or body.get("title") != title:
            return CheckerResult.CORRUPT
        q = s.get(
            f"{url}/api/audit/search",
            headers=headers,
            params={"category": "network", "needle": "incident-"},
            timeout=TIMEOUT,
        )
        if q.status_code != 200 or not isinstance(q.json().get("items"), list):
            return CheckerResult.MUMBLE
        return CheckerResult.OK
    except requests.exceptions.RequestException:
        return CheckerResult.DOWN
    except Exception:
        return CheckerResult.MUMBLE


def put(target_ip, target_port, flag=None):
    if flag is None:
        flag = generate_random_flag()
    if not FLAG_RE.match(flag):
        return CheckerResult.CHECK_FAILED
    url = base_url(target_ip, target_port)
    try:
        s = requests.Session()
        username, password, token = register(s, url)
        case_id, _ = create_case(s, url, token, flag)
        flag_id = json.dumps({"u": username, "p": password, "id": case_id}, separators=(",", ":"))
        items = load_state()
        items.append({"ts": int(time.time()), "flag": flag, "flag_id": flag_id})
        save_state(items)
        print(flag_id)
        return CheckerResult.OK
    except requests.exceptions.RequestException:
        return CheckerResult.DOWN
    except Exception:
        return CheckerResult.MUMBLE


def get(target_ip, target_port, flag_id=None, expected_flag=None):
    items = load_state()
    if flag_id is None:
        if not items:
            return CheckerResult.CHECK_FAILED
        flag_id = items[-1]["flag_id"]
        expected_flag = items[-1]["flag"]
    if expected_flag is None:
        for item in reversed(items):
            if item.get("flag_id") == flag_id:
                expected_flag = item.get("flag")
                break
    if not expected_flag or not FLAG_RE.match(expected_flag):
        return CheckerResult.CHECK_FAILED
    url = base_url(target_ip, target_port)
    try:
        meta = json.loads(flag_id)
        s = requests.Session()
        login = s.post(
            f"{url}/api/sessions/login",
            json={"username": meta["u"], "password": meta["p"]},
            timeout=TIMEOUT,
        )
        if login.status_code != 200:
            return CheckerResult.CORRUPT
        token = login.json().get("token")
        headers = {"Authorization": f"Bearer {token}"}
        r = s.get(f"{url}/api/cases/{int(meta['id'])}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 404:
            return CheckerResult.CORRUPT
        if r.status_code != 200:
            return CheckerResult.MUMBLE
        if r.json().get("secret_note") != expected_flag:
            return CheckerResult.CORRUPT
        return CheckerResult.OK
    except requests.exceptions.RequestException:
        return CheckerResult.DOWN
    except Exception:
        return CheckerResult.MUMBLE


def get_flags(target_ip, target_port):
    for item in load_state():
        flag = item.get("flag")
        if flag and FLAG_RE.match(flag):
            print(flag)
    return CheckerResult.OK


def execute_command(command, target_ip, target_port, args):
    if command == "check":
        return check(target_ip, target_port, *args)
    if command == "put":
        return put(target_ip, target_port, args[0] if args else None)
    if command == "get":
        return get(target_ip, target_port, args[0] if len(args) >= 1 else None, args[1] if len(args) >= 2 else None)
    if command == "get_flags":
        return get_flags(target_ip, target_port)
    return CheckerResult.CHECK_FAILED


def main():
    if len(sys.argv) < 4:
        print("Usage: checker.py <ip> <port> <check|put|get|get_flags> [flag_id] [flag]", file=sys.stderr)
        sys.exit(CheckerResult.CHECK_FAILED)
    target_ip = sys.argv[1]
    try:
        target_port = int(sys.argv[2])
    except ValueError:
        sys.exit(CheckerResult.CHECK_FAILED)
    command = sys.argv[3]
    result = execute_command(command, target_ip, target_port, sys.argv[4:])
    sys.exit(result)


if __name__ == "__main__":
    main()
