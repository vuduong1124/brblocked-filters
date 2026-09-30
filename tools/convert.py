#!/usr/bin/env python3
"""Chuyển danh sách chặn mã nguồn mở sang cú pháp của BRBlocked.

Đầu ra trong lists/: mỗi danh sách một file <id>.txt gồm
  ||domain^            chặn domain và mọi subdomain
  site.com##selector   ẩn phần tử trên site (không có rule ẩn chung cho mọi site)
và lists/index.txt (tách bằng tab): sha256, tên file, số domain, số rule ẩn, ngày cập nhật, tên, mô tả.

Chỉ lấy rule app hiểu đúng; rule cú pháp phức tạp bị bỏ để không chặn nhầm:
- hosts: dòng "0.0.0.0 domain" hoặc "127.0.0.1 domain".
- Adblock Plus: "||domain^" không kèm tùy chọn hoặc chỉ kèm $third-party, $popup, $document, $all;
  domain có ngoại lệ "@@||..." (kể cả subdomain) bị bỏ, vì app chặn cả domain.
- Ẩn phần tử: "a.com,b.com##selector" không có "~", không phải selector mở rộng (:has-text, :-abp-...),
  selector có ngoại lệ "#@#" bị bỏ.
- Domain trong tools/never-block.txt (và domain cha của chúng) không bao giờ bị chặn.

Nguồn tải lỗi hoặc kết quả mất quá nửa số domain so với bản cũ thì giữ bản cũ.

Chạy: python3 tools/convert.py [--cache thư_mục] (--cache: đọc file gốc đã tải sẵn, tên <id>.src).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "lists")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
IP = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
SKIP_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0"}
NET_OPTIONS = {"third-party", "3p", "popup", "document", "doc", "all"}
# Selector mở rộng của uBlock/AdGuard mà CSS thường không hiểu.
EXTENDED = re.compile(
    r":-abp-|:has-text\(|:contains\(|:xpath\(|:style\(|:matches-css|:upward\(|:remove\(|:watch-attr|"
    r":min-text-length|:matches-path|:others\(|:if\(|:if-not\(|:nth-ancestor|:matches-attr|:matches-prop|"
    r":remove-attr|:remove-class|:shadow"
)
MAX_SELECTOR = 400


def load_never_block():
    with open(os.path.join(ROOT, "tools", "never-block.txt"), encoding="utf-8") as f:
        return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}


def parents(domain):
    """Chính domain và các domain cha có ít nhất hai nhãn."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def is_essential(domain, essential):
    """Chặn domain này có làm hỏng domain thiết yếu không (chính nó hoặc là domain cha của nó)."""
    return any(e == domain or e.endswith("." + domain) for e in essential)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "brblocked-filters/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def parse_hosts(text):
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            continue
        for d in parts[1:]:
            d = d.lower().rstrip(".")
            if d not in SKIP_HOSTS and not IP.match(d) and DOMAIN.match(d):
                domains.add(d)
    return domains, {}


def parse_abp(text):
    domains, exceptions = set(), set()
    cosmetic, cosmetic_exceptions = {}, set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        if "#@#" in line:
            cosmetic_exceptions.add(line.split("#@#", 1)[1])
            continue
        if re.search(r"#[?$%]#", line):
            continue
        if "##" in line:
            sites, sel = line.split("##", 1)
            if not sites or "~" in sites or sel.startswith("+js") or sel.startswith("^"):
                continue
            if EXTENDED.search(sel) or len(sel) > MAX_SELECTOR or "{" in sel or "}" in sel:
                continue
            for s in sites.split(","):
                s = s.strip().lower()
                if "*" in s or not DOMAIN.match(s):
                    continue
                cosmetic.setdefault(s, []).append(sel)
            continue
        if line.startswith("@@||"):
            host = re.match(r"@@\|\|([a-z0-9._-]+)", line.lower())
            if host:
                exceptions.add(host.group(1).rstrip("."))
            continue
        m = re.match(r"^\|\|([a-z0-9._-]+)\^(?:\$(.+))?$", line.lower())
        if not m:
            continue
        d, opts = m.group(1).rstrip("."), m.group(2)
        if opts and not {o.strip() for o in opts.split(",")} <= NET_OPTIONS:
            continue
        if DOMAIN.match(d) and not IP.match(d):
            domains.add(d)
    # Domain có ngoại lệ ở chính nó hoặc ở subdomain: app chặn cả domain nên bỏ để khỏi chặn nhầm.
    excepted = set()
    for e in exceptions:
        excepted.update(parents(e))
    domains = {d for d in domains if d not in excepted}
    cosmetic = {s: sorted({x for x in sels if x not in cosmetic_exceptions}) for s, sels in cosmetic.items()}
    return domains, {s: v for s, v in cosmetic.items() if v}


def minimize(domains):
    """Bỏ subdomain khi domain cha đã có trong danh sách."""
    return {d for d in domains if not any(p in domains for p in parents(d)[1:])}


def convert(src, text, essential, today):
    domains, cosmetic = (parse_hosts if src["format"] == "hosts" else parse_abp)(text)
    domains = minimize({d for d in domains if not is_essential(d, essential)})
    n_cosmetic = sum(len(v) for v in cosmetic.values())
    lines = [
        "! Title: " + src["title"],
        "! Source: " + src["url"],
        "! License: " + src["license"],
        "! Converted: " + today + " by https://github.com/vuduong1124/brblocked-filters/blob/main/tools/convert.py",
        "! Domains: %d" % len(domains),
        "! Cosmetic: %d" % n_cosmetic,
    ]
    lines += ["||%s^" % d for d in sorted(domains)]
    for site in sorted(cosmetic):
        lines += ["%s##%s" % (site, sel) for sel in cosmetic[site]]
    return "\n".join(lines) + "\n", len(domains), n_cosmetic


def strip_date(body):
    return "\n".join(l for l in body.splitlines() if not l.startswith("! Converted: "))


def old_count(path):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("! Domains: "):
                    return int(line.split(":")[1])
                if not line.startswith("!"):
                    break
    except OSError:
        pass
    return 0


def read_index():
    rows = {}
    try:
        with open(os.path.join(OUT, "index.txt"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                cols = line.rstrip("\n").split("\t")
                rows[cols[1]] = cols
    except OSError:
        pass
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", help="thư mục chứa file gốc <id>.src đã tải sẵn")
    args = ap.parse_args()
    with open(os.path.join(ROOT, "tools", "sources.json"), encoding="utf-8") as f:
        sources = json.load(f)
    essential = load_never_block()
    today = datetime.date.today().isoformat()
    os.makedirs(OUT, exist_ok=True)
    previous = read_index()
    rows, failed = [], []
    for src in sources:
        name = src["id"] + ".txt"
        path = os.path.join(OUT, name)
        try:
            if args.cache:
                with open(os.path.join(args.cache, src["id"] + ".src"), encoding="utf-8", errors="replace") as f:
                    text = f.read()
            else:
                text = fetch(src["url"])
            body, n_domains, n_cosmetic = convert(src, text, essential, today)
            before = old_count(path)
            if n_domains + n_cosmetic == 0 or (before and n_domains < before // 2):
                raise ValueError("chỉ còn %d domain (bản cũ %d)" % (n_domains, before))
        except Exception as e:  # giữ bản cũ nếu có
            print("%s: lỗi %s" % (src["id"], e), file=sys.stderr)
            failed.append(src["id"])
            if name in previous and os.path.exists(path):
                rows.append(previous[name])
            continue
        old = previous.get(name)
        # Nội dung không đổi (bỏ qua dòng ngày chuyển đổi) thì giữ file và ngày cũ, tránh commit mỗi ngày.
        if old and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                if strip_date(f.read()) == strip_date(body):
                    rows.append(old)
                    print("%s: không đổi" % src["id"])
                    continue
        data = body.encode("utf-8")
        with open(path, "wb") as f:
            f.write(data)
        sha = hashlib.sha256(data).hexdigest()
        rows.append([sha, name, str(n_domains), str(n_cosmetic), today, src["title"], src["description"]])
        print("%s: %d domain, %d ẩn phần tử" % (src["id"], n_domains, n_cosmetic))
    known = {r[1] for r in rows}
    for f in os.listdir(OUT):
        if f.endswith(".txt") and f != "index.txt" and f not in known:
            os.remove(os.path.join(OUT, f))
    with open(os.path.join(OUT, "index.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# sha256\tfile\tdomains\tcosmetic\tupdated\ttitle\tdescription\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    if len(failed) == len(sources):
        sys.exit("mọi nguồn đều lỗi")


if __name__ == "__main__":
    main()
