#!/usr/bin/env python3
# whole.py - read-only questions about the WHOLE two weeks, asked of the Hive's own Elasticsearch.
# usage: python3 whole.py hp | geo | creds | ids | os | ips
import json, re, sys, urllib.request, urllib.error

BASE = "http://127.0.0.1:64298"
IDX = ",".join("logstash-2026.10.%02d" % d for d in range(17, 32))
ES = BASE + "/" + IDX + "/_search?ignore_unavailable=true"
RANGE = {"range": {"@timestamp": {"gte": "2026-10-17T00:00:00Z", "lt": "2026-10-31T20:00:00Z"}}}
HP = ["Cowrie","Honeytrap","Sentrypeer","Dionaea","RDPHoneypot","Redishoneypot","Tanner","H0neytr4p",
      "Heralding","Mailoney","ConPot","Adbhoney","Ciscoasa","Elasticpot","Ipphoney","Medpot","Miniprint",
      "Honeyaml","Wordpot","CitrixHoneypot","Log4pot","Dicompot","Ddospot","Endlessh","Glutton"]
# map your own T-Pot hostnames (the t-pot_hostname field) to short names; edit these to match your nodes
NAMES = {"<hive-hostname>": "hive-aws", "tpot-azure-sensor": "azure", "tpot-gcp-sensor": "gcp"}
_ok = {}

def clean(s):
    s = str(s)
    for a, b in NAMES.items():
        s = s.replace(a, b)
    return s

def q(body):
    body.setdefault("size", 0)
    req = urllib.request.Request(ES, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=600))
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()[:300]}
    except Exception as e:
        return {"error": str(e)}

def flt(match=None, hp=False, exists=None):
    f = [RANGE]
    for k, v in (match or {}).items():
        f.append({"match_phrase": {k: v}})
    if hp:
        f.append({"bool": {"should": [{"match_phrase": {"type": t}} for t in HP], "minimum_should_match": 1}})
    if exists:
        f.append({"exists": {"field": exists}})
    return {"bool": {"filter": f}}

def usable(field, flt_):
    if field in _ok:
        return _ok[field]
    for f in (field, field + ".keyword"):
        r = q({"query": flt_, "aggs": {"t": {"terms": {"field": f, "size": 1}}}})
        if "aggregations" in r:
            _ok[field] = f
            return f
    _ok[field] = None
    return None

def total(flt_):
    r = q({"track_total_hits": True, "query": flt_})
    try:
        return r["hits"]["total"]["value"]
    except Exception:
        return 0

def terms(title, field, flt_, size=10, show_ips=True, width=70):
    print("\n== %s ==" % title)
    f = usable(field, flt_)
    if not f:
        print("  field not usable:", field)
        return []
    a = {"terms": {"field": f, "size": size}}
    if show_ips:
        a["aggs"] = {"ips": {"cardinality": {"field": usable("src_ip", flt_) or "src_ip"}}}
    r = q({"track_total_hits": True, "query": flt_, "aggs": {"t": a}})
    if "aggregations" not in r:
        print("  FAILED:", str(r)[:200]); return []
    tot = r["hits"]["total"]["value"]
    out = []
    for i, b in enumerate(r["aggregations"]["t"]["buckets"], 1):
        pct = 100.0 * b["doc_count"] / tot if tot else 0
        extra = "  ips=%d" % b["ips"]["value"] if show_ips else ""
        print("%2d. %-*s %9s  %5.1f%%%s" % (i, width, clean(b["key"])[:width], format(b["doc_count"], ","), pct, extra))
        out.append((b["key"], b["doc_count"]))
    print("    (total in this view: %s)" % format(tot, ","))
    return out

def top_ip_profiles(flt_, n=10):
    print("\n== TOP %d SOURCE IPs, ONE LINE EACH ==" % n)
    ipf = usable("src_ip", flt_) or "src_ip"
    cf = usable("geoip.country_name", flt_)
    af = usable("geoip.as_org", flt_)
    rf = usable("ip_rep", flt_)
    hf = usable("t-pot_hostname", flt_)
    sub = {"types": {"terms": {"field": usable("type", flt_) or "type", "size": 4}},
           "ports": {"terms": {"field": usable("dest_port", flt_) or "dest_port", "size": 3}},
           "first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}},
           "days": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day", "min_doc_count": 1}}}
    if cf: sub["country"] = {"terms": {"field": cf, "size": 1}}
    if af: sub["asn"] = {"terms": {"field": af, "size": 1}}
    if rf: sub["rep"] = {"terms": {"field": rf, "size": 2}}
    if hf: sub["sens"] = {"terms": {"field": hf, "size": 3}}
    r = q({"track_total_hits": True, "query": flt_, "aggs": {"ip": {"terms": {"field": ipf, "size": n}, "aggs": sub}}})
    if "aggregations" not in r:
        print("  FAILED:", str(r)[:200]); return []
    tot = r["hits"]["total"]["value"]
    ips = []
    for i, b in enumerate(r["aggregations"]["ip"]["buckets"], 1):
        k = lambda name: [x["key"] for x in b.get(name, {}).get("buckets", [])]
        ips.append(b["key"])
        print("%2d. %s  %s events (%.1f%%)" % (i, b["key"], format(b["doc_count"], ","), 100.0 * b["doc_count"] / tot))
        print("    country: %s | AS: %s | ip_rep: %s" % (", ".join(map(clean, k("country"))) or "-", ", ".join(map(clean, k("asn"))) or "-", ", ".join(map(clean, k("rep"))) or "-"))
        print("    honeypots: %s | ports: %s | sensors: %s" % (", ".join(map(clean, k("types"))), ", ".join(map(str, k("ports"))), ", ".join(map(clean, k("sens"))) or "-"))
        print("    first %s | last %s | active days: %d" % (b["first"].get("value_as_string", "?")[:16], b["last"].get("value_as_string", "?")[:16], len(b["days"]["buckets"])))
    return ips

def field_names(title, flt_):
    print("\n== %s: FIELD NAMES ONLY (no values) ==" % title)
    r = q({"size": 1, "query": flt_})
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        print("  no document"); return []
    names = []
    def walk(d, p=""):
        for k, v in d.items():
            if isinstance(v, dict): walk(v, p + k + ".")
            else: names.append(p + k)
    walk(hits[0]["_source"])
    print("  " + ", ".join(sorted(names)))
    return names

def head(title):
    print("#" * 70); print("# " + title); print("#" * 70)

def mode_hp():
    head("HONEYPOT EVENTS, 17 Oct 00:00 to 31 Oct 20:00 UTC")
    hp = flt(hp=True)
    print("honeypot events:", format(total(hp), ","), "(my earlier script said 1,257,851)")
    terms("WHICH HONEYPOT WAS ATTACKED MOST", "type", hp, 12)
    terms("EVENTS PER SENSOR", "t-pot_hostname", hp, 5)
    top_ip_profiles(hp, 10)

def mode_geo():
    head("WHERE FROM, WHICH PORTS")
    hp = flt(hp=True)
    terms("TOP COUNTRIES", "geoip.country_name", hp, 10)
    terms("TOP ATTACKER NETWORKS (AS organisation)", "geoip.as_org", hp, 12)
    terms("TOP DESTINATION PORTS", "dest_port", hp, 12)
    terms("T-POT OWN IP REPUTATION TAG", "ip_rep", hp, 6)

def mode_creds():
    head("USERNAMES AND PASSWORDS (every honeypot that records them)")
    f = flt(hp=True, exists="username")
    print("events with a username:", format(total(f), ","))
    terms("TOP USERNAMES", "username", f, 12, show_ips=False, width=30)
    f2 = flt(hp=True, exists="password")
    terms("TOP PASSWORDS", "password", f2, 12, show_ips=False, width=30)
    terms("USERNAMES BY HONEYPOT", "type", f, 6, show_ips=False, width=30)

def mode_ids():
    head("SURICATA")
    s = flt({"type": "Suricata"})
    print("Suricata documents:", format(total(s), ","))
    terms("WHAT KIND OF SURICATA RECORD", "event_type", s, 8, show_ips=False, width=30)
    a = flt({"type": "Suricata", "event_type": "alert"})
    print("alerts:", format(total(a), ","))
    f = usable("alert.signature", a)
    if f:
        r = q({"query": a, "aggs": {"s": {"terms": {"field": f, "size": 1000}, "aggs": {"sid": {"terms": {"field": "alert.signature_id", "size": 1}}}}}})
        b = r.get("aggregations", {}).get("s", {}).get("buckets", [])
        print("\n== TOP SIGNATURES, WITHOUT SURICATA PACKET-DECODER NOISE ==")
        n = 0
        for x in b:
            if x["key"].startswith("SURICATA"): continue
            n += 1
            sid = (x["sid"]["buckets"] or [{"key": "?"}])[0]["key"]
            print("%2d. %-62s %8s  sid %s" % (n, x["key"][:62], format(x["doc_count"], ","), sid))
            if n == 15: break
        print("\n== THE NOISE (decoder / protocol events, not attacks) ==")
        n = 0
        for x in b:
            if not x["key"].startswith("SURICATA"): continue
            n += 1
            print("%2d. %-62s %8s" % (n, x["key"][:62], format(x["doc_count"], ",")))
            if n == 4: break
        cve = {}
        for x in b:
            for c in set(re.findall(r"CVE-\d{4}-\d{4,}", x["key"])):
                cve.setdefault(c, [0, x["key"]]); cve[c][0] += x["doc_count"]
        print("\n== CVE IDs FOUND INSIDE SIGNATURE NAMES ==")
        for i, (c, (n_, nm)) in enumerate(sorted(cve.items(), key=lambda z: -z[1][0])[:15], 1):
            print("%2d. %-16s %8s  %s" % (i, c, format(n_, ","), nm[:52]))
        if not cve: print("  none")
    terms("TOP alert.cve_id FIELD (as Kibana shows it)", "alert.cve_id", a, 15, show_ips=False, width=40)
    terms("ALERT CATEGORIES", "alert.category", a, 10, show_ips=False, width=45)
    terms("TOP SOURCE IPs OF ALERTS", "src_ip", a, 10, show_ips=False, width=20)
    field_names("SURICATA ALERT", a)

def mode_os():
    head("p0f (passive OS fingerprinting)")
    p = flt({"type": "P0f"})
    print("P0f documents:", format(total(p), ","))
    names = field_names("P0F", p)
    osf = [n for n in names if n in ("os", "p0f.os", "os_name")] or [n for n in names if n.endswith("os")]
    sub = [n for n in names if n in ("subj", "subject")]
    for o in osf[:1]:
        terms("OPERATING SYSTEMS, all p0f records (field %s)" % o, o, p, 15, show_ips=False, width=40)
        for sname in sub[:1]:
            terms("WHICH SIDE WAS FINGERPRINTED (%s)" % sname, sname, p, 4, show_ips=False, width=20)
            for side in ("cli", "srv"):
                terms("OS where %s = %s" % (sname, side), o, flt({"type": "P0f", sname: side}), 10, show_ips=False, width=40)
    if not osf: print("  no os field found - send me the field names above")

def mode_ips():
    head("TOP IPs ACROSS SURICATA ALERTS, WITH THEIR HONEYPOT ACTIVITY")
    a = flt({"type": "Suricata", "event_type": "alert"})
    terms("TOP SOURCE IPs OF ALERTS", "src_ip", a, 10, show_ips=False, width=20)

MODES = {"hp": mode_hp, "geo": mode_geo, "creds": mode_creds, "ids": mode_ids, "os": mode_os, "ips": mode_ips}
if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "hp"
    if m == "all":
        for k in ("hp", "geo", "creds", "ids", "os"): MODES[k]()
    elif m in MODES:
        MODES[m]()
    else:
        print("modes:", ", ".join(MODES), "or all")
