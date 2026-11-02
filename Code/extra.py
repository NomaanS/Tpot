#!/usr/bin/env python3
# extra.py - more read-only questions for the report. Needs whole.py in the same folder.
# usage: python3 extra.py bynode | ports | banat | ip 109.198.192.113 [more IPs]
import sys
from whole import *

def agg(field, f, n=3):
    fld = usable(field, f)
    if not fld: return []
    r = q({"query": f, "aggs": {"t": {"terms": {"field": fld, "size": n}}}})
    return [(clean(b["key"]), b["doc_count"]) for b in r.get("aggregations", {}).get("t", {}).get("buckets", [])]

def line(pairs):
    return ", ".join("%s %s" % (k, format(v, ",")) for k, v in pairs) or "-"

def mode_bynode():
    head("WHICH HONEYPOT RAN ON WHICH NODE (events)")
    hp = flt(hp=True)
    tf, nf = usable("type", hp), usable("t-pot_hostname", hp)
    r = q({"query": hp, "aggs": {"t": {"terms": {"field": tf, "size": 20}, "aggs": {"n": {"terms": {"field": nf, "size": 5}}}}}})
    nodes = ["hive-aws", "azure", "gcp"]
    print("%-14s %9s  %s" % ("honeypot", "total", " ".join("%9s" % n for n in nodes)))
    for b in r.get("aggregations", {}).get("t", {}).get("buckets", []):
        per = {clean(x["key"]): x["doc_count"] for x in b["n"]["buckets"]}
        print("%-14s %9s  %s" % (clean(b["key"])[:14], format(b["doc_count"], ","), " ".join("%9s" % format(per.get(n, 0), ",") for n in nodes)))

def mode_ports():
    head("WHAT EACH BUSY PORT WAS USED FOR")
    for p in (5060, 3389, 22, 445, 1433, 3306, 23, 6379):
        f = flt({"dest_port": p}, hp=True)
        print("\nport %d: %s events" % (p, format(total(f), ",")))
        print("  honeypots : " + line(agg("type", f, 3)))
        print("  top IPs   : " + line(agg("src_ip", f, 3)))

def per_day(f):
    r = q({"query": f, "aggs": {"d": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day", "min_doc_count": 1},
           "aggs": {"ips": {"cardinality": {"field": usable("src_ip", f) or "src_ip"}}}}}})
    print("\n== EVENTS PER DAY ==")
    for b in r.get("aggregations", {}).get("d", {}).get("buckets", []):
        print("  %s  %9s events  %3d ips" % (b["key_as_string"][:10], format(b["doc_count"], ","), b["ips"]["value"]))

def mode_banat():
    head("BANATSYNC SRL, THE BIGGEST NETWORK")
    b = flt({"geoip.as_org": "Banatsync Srl"}, hp=True)
    print("events:", format(total(b), ","))
    terms("TOP 10 ADDRESSES", "src_ip", b, 10, show_ips=False, width=20)
    terms("BY NODE", "t-pot_hostname", b, 5)
    terms("BY HONEYPOT", "type", b, 5, show_ips=False, width=20)
    terms("EVENT KINDS", "eventid", b, 8, show_ips=False, width=40)
    terms("USERNAMES", "username", b, 6, show_ips=False, width=20)
    terms("PASSWORDS", "password", b, 6, show_ips=False, width=20)
    terms("COMMANDS TYPED", "input", b, 5, show_ips=False, width=50)
    per_day(b)

def mode_ip(ips):
    for ip in ips:
        f = flt({"src_ip": ip}, hp=True)
        head("ONE ADDRESS: " + ip)
        print("events:", format(total(f), ","))
        top_ip_profiles(f, 1)
        terms("EVENT KINDS", "eventid", f, 6, show_ips=False, width=40)
        terms("USERNAMES", "username", f, 4, show_ips=False, width=20)
        terms("PASSWORDS", "password", f, 4, show_ips=False, width=20)
        r = q({"query": f, "aggs": {"p": {"cardinality": {"field": usable("password", f) or "password"}}}})
        print("\ndistinct passwords tried:", r.get("aggregations", {}).get("p", {}).get("value", "n/a"))
        r = q({"query": f, "aggs": {"h": {"date_histogram": {"field": "@timestamp", "calendar_interval": "hour", "min_doc_count": 1}}}})
        hrs = sorted(r.get("aggregations", {}).get("h", {}).get("buckets", []), key=lambda x: -x["doc_count"])
        print("active hours: %d | busiest hours (UTC):" % len(hrs))
        for x in hrs[:4]:
            print("  %s  %s events" % (x["key_as_string"][:13], format(x["doc_count"], ",")))

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else ""
    if m == "bynode": mode_bynode()
    elif m == "ports": mode_ports()
    elif m == "banat": mode_banat()
    elif m == "ip" and len(sys.argv) > 2: mode_ip(sys.argv[2:])
    else: print("usage: python3 extra.py bynode | ports | banat | ip <address> [more addresses]")
