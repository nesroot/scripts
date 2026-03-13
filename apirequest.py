import requests
import threading
import time

# ================= CONFIG =================

THREADS = 5
START_ID = 1000
END_ID = 1050
DELAY = 0.2

PLACEHOLDER = "§ID§"

# =============== REQUEST RAW ==============

RAW_REQUEST = """
POST /endpoint HTTP/1.1
Host: api.target.com
Authorization: Bearer TOKEN123
Content-Type: application/json

{
 "client_id": "§ID§",
 "type": "A"
}
"""

# ==========================================


def parse_request(raw):

    raw = raw.strip()
    head, body = raw.split("\n\n", 1)

    lines = head.splitlines()
    method, path, _ = lines[0].split()

    headers = {}
    host = ""

    for line in lines[1:]:
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

        if k.lower() == "host":
            host = v.strip()

    url = f"https://{host}{path}"

    return method, url, headers, body


method, url, headers, body = parse_request(RAW_REQUEST)

baseline_len = None
lock = threading.Lock()


def send_request(value):

    global baseline_len

    data = body.replace(PLACEHOLDER, str(value))

    try:

        start = time.time()

        r = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            timeout=10
        )

        elapsed = round(time.time() - start, 3)

        length = len(r.text)

        with lock:

            if baseline_len is None:
                baseline_len = length

            interesting = ""

            if r.status_code != 200:
                interesting = "STATUS_DIFF"

            if length != baseline_len:
                interesting += " LEN_DIFF"

            print(
                f"[{r.status_code}] id={value} "
                f"len={length} "
                f"time={elapsed}s "
                f"{interesting}"
            )

    except Exception as e:

        print(f"[ERROR] id={value} {e}")


def worker(queue):

    while True:

        try:
            value = queue.pop(0)
        except:
            return

        send_request(value)

        time.sleep(DELAY)


def run():

    queue = list(range(START_ID, END_ID))

    threads = []

    for _ in range(THREADS):

        t = threading.Thread(target=worker, args=(queue,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    run()
