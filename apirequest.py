import requests
import threading
import queue
import hashlib
import json
import random
import time
from rich import print
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================

THREADS = 1
START = 1802841164
END = 1802842270
DELAY = 1
#§id§
PLACEHOLDER = "§id§"

EXTRACT_FIELD = "data.result"

IGNORE_FIELDS = [
"timestamp",
"request_id",
"trace_id"
]

PROXIES = None
#PROXIES = {"http":"http://127.0.0.1:8080","https":"http://127.0.0.1:8080"}

USER_AGENTS = [
"Mozilla/5.0",
"Chrome/120",
"Safari/17",
"PostmanRuntime/7.36"
]

# =============== RAW REQUEST ==============

RAW_REQUEST = """

"""

# ==========================================


def parse_raw_request(raw):

    raw = raw.strip()
    head, body = raw.split("\n\n",1)

    lines = head.splitlines()
    method, path, _ = lines[0].split()

    headers = {}
    host = ""

    for line in lines[1:]:

        k,v = line.split(":",1)
        headers[k.strip()] = v.strip()

        if k.lower() == "host":
            host = v.strip()

    headers.pop("Content-Length",None)

    url = f"https://{host}{path}"

    return method,url,headers,body


def fingerprint(text):

    try:

        data = json.loads(text)

        for k in IGNORE_FIELDS:
            data.pop(k,None)

        normalized = json.dumps(data,sort_keys=True)

    except:

        normalized = text

    return hashlib.md5(normalized.encode()).hexdigest()


def flatten_json(data,prefix=""):

    items = {}

    if isinstance(data,dict):

        for k,v in data.items():

            new_key = f"{prefix}.{k}" if prefix else k
            items.update(flatten_json(v,new_key))

    elif isinstance(data,list):

        for i,v in enumerate(data):

            new_key = f"{prefix}.{i}"
            items.update(flatten_json(v,new_key))

    else:

        items[prefix] = data

    return items


def extract_field(text,path):

    try:

        data = json.loads(text)
        parts = path.split(".")

        for p in parts:

            if p.isdigit():
                data = data[int(p)]
            else:
                data = data.get(p)

            if data is None:
                return None

        return data

    except:

        return None


def mutate_headers(headers):

    h = headers.copy()

    h["User-Agent"] = random.choice(USER_AGENTS)

    ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    h["X-Forwarded-For"] = ip
    h["X-Real-IP"] = ip

    return h


def detect_field_changes(text):

    global baseline_fields

    try:

        data = json.loads(text)
        flat = flatten_json(data)

        if baseline_fields is None:
            baseline_fields = flat
            return {}

        changes = {}

        for k,v in flat.items():

            if k in baseline_fields and baseline_fields[k] != v:
                changes[k] = v

        return changes

    except:

        return {}


def log_hit(value,response):

    with open("hits.txt","a") as f:

        f.write(
            f"\nVALUE:{value}\n"
            f"STATUS:{response.status_code}\n"
            f"{response.text}\n"
            f"{'-'*50}\n"
        )


def send_request(value):

    global baseline_fp

    data = body.replace(PLACEHOLDER,str(value))

    try:

        start = time.time()

        r = requests.request(
            method,
            url,
            headers=mutate_headers(headers),
            data=data,
            timeout=10,
            proxies=PROXIES,
            verify=False
        )

        elapsed = round(time.time()-start,3)

        fp = fingerprint(r.text)

        extracted = extract_field(r.text,EXTRACT_FIELD)

        changes = detect_field_changes(r.text)

        with lock:

            interesting = ""

            if baseline_fp is None:
                baseline_fp = fp

            if r.status_code != 200:
                interesting += " STATUS_DIFF"

            if fp != baseline_fp:
                interesting += " CONTENT_DIFF"

            if r.status_code == 429:
                interesting += " RATE_LIMIT"

            print(
                f"[{r.status_code}] id={value} "
                f"time={elapsed}s "
                f"extracted={extracted} "
                f"{interesting}"
            )

            if changes:
                print(f"[yellow]JSON_FIELDS_CHANGED:[/yellow] {changes}")

            if interesting or changes:
                log_hit(value,r)

    except Exception as e:

        print(f"[red]ERROR[/red] {value} {e}")


def worker():

    while True:

        try:
            value = q.get_nowait()
        except queue.Empty:
            return

        send_request(value)

        time.sleep(DELAY)

        q.task_done()


# ================= RUN ====================

try:

    method,url,headers,body = parse_raw_request(RAW_REQUEST)

    baseline_fp = None
    baseline_fields = None

    q = queue.Queue()
    lock = threading.Lock()

    for i in range(START,END):
        q.put(i)

    threads = []

    for _ in range(THREADS):

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopped by user")
