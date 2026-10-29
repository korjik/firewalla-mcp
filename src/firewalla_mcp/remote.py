"""Dependency-free helper sent in memory to Python 3 on the router.

Never installed on the router. Only this operation dispatch is reachable.
Raw command/config output is projected here before crossing SSH.
"""
import ipaddress
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import time

LIMIT = 131072

class Unsupported(Exception):
    pass


def run(argv, seconds=5):
    """Bound time AND bytes while reading; discard stderr and never return it."""
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        raise Unsupported("utility unavailable")
    data = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            end = time.monotonic() + seconds
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    raise Unsupported("command timeout")
                events = sel.select(left)
                if not events:
                    raise Unsupported("command timeout")
                chunk = os.read(p.stdout.fileno(), 8192)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > LIMIT:
                    raise Unsupported("output limit exceeded; narrow query")
        if p.wait(timeout=max(.01, end-time.monotonic())) != 0:
            raise Unsupported("command unavailable or permission denied")
        return data.decode("utf-8", errors="strict")
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        p.stdout.close()


def atom(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:@/+*-]{1,80}", value):
        raise Unsupported("unrecognized field format")
    return value


def ip(value):
    return str(ipaddress.ip_address(value))


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("invalid port")
    return value


def port_range(value):
    pieces = str(value).replace(":", "-").split("-")
    if not 1 <= len(pieces) <= 2 or not all(x.isdigit() for x in pieces):
        raise Unsupported("unknown port range")
    nums = [port(int(x)) for x in pieces]
    if nums[0] > nums[-1]:
        raise Unsupported("reversed port range")
    return nums


def network(kind):
    commands = {"interfaces": ["ip", "-j", "-d", "link", "show"],
                "addresses": ["ip", "-j", "address", "show"],
                "routes": ["ip", "-j", "route", "show", "table", "all"],
                "rules": ["ip", "-j", "rule", "show"],
                "neighbors": ["ip", "-j", "neighbor", "show"]}
    rows = json.loads(run(commands[kind]))
    if not isinstance(rows, list):
        raise Unsupported("unknown ip JSON schema")
    # Explicit projection: omit aliases, arbitrary names, extensions, and nested secrets.
    keys = {"ifindex", "ifname", "mtu", "operstate", "address", "dst", "gateway", "dev", "table", "priority", "src", "prefsrc", "lladdr", "protocol"}
    out = []
    for row in rows[:256]:
        item = {k: v for k,v in row.items() if k in keys and isinstance(v,(str,int))}
        if "addr_info" in row:
            item["addresses"] = [{"address": ip(a["local"]), "prefixlen": int(a["prefixlen"])} for a in row["addr_info"][:32]]
        info = row.get("linkinfo", {})
        if info.get("info_kind") == "vlan":
            item["vlan_id"] = int(info.get("info_data", {})["id"])
        out.append(item)
    return {"rows": out, "truncated": len(rows)>256}


def mappings():
    data = json.loads(run(["redis-cli", "--raw", "GET", "extension.portforward.config"]))
    if not isinstance(data, dict) or not isinstance(data.get("maps"), list):
        raise Unsupported("unknown port forwarding schema")
    out = []
    for row in data["maps"][:128]:
        if row.get("protocol") not in ("tcp", "udp"):
            raise Unsupported("unknown forwarding protocol")
        item = {"protocol": row["protocol"], "external_ports": port_range(row["dport"]),
                "destination": ip(row["toIP"]), "destination_ports": port_range(row["toPort"])}
        item["enabled"] = row.get("enabled", True) is True
        out.append(item)
    return {"configured_mappings": out, "truncated": len(data["maps"])>128,
            "note": "Configured intent only; kernel rules and external probes are separate evidence."}


def firewall(table):
    # Numeric listing omits arbitrary comments and log prefixes; expose only parsed rows.
    raw = run(["sudo", "-n", "iptables", "-t", table, "-L", "-n", "-v", "-x"])
    rows, chain = [], None
    for line in raw.splitlines():
        if line.startswith("Chain "):
            chain = atom(line.split()[1])
        parts = line.split()
        if len(parts) >= 9 and parts[0].isdigit() and parts[1].isdigit():
            rows.append(dict(chain=chain, packets=int(parts[0]), bytes=int(parts[1]),
                             target=atom(parts[2]), protocol=atom(parts[3]),
                             input=atom(parts[5]), output=atom(parts[6]),
                             source=str(ipaddress.ip_network(parts[7], strict=False)),
                             destination=str(ipaddress.ip_network(parts[8], strict=False))))
    return {"rows": rows[:256], "truncated": len(rows)>256,
            "note": "IPv4 counters only; match extensions and NAT translations omitted. Not a complete effective policy."}


def dispatch(op, args):
    if op == "services":
        result = {}
        for unit in ("firemain", "firemon", "firerouter", "redis-server", "openvpn@server"):
            raw = run(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState", "--no-pager"])
            fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
            result[unit] = {key: atom(fields[key]) for key in ("LoadState", "ActiveState", "SubState") if key in fields}
        return {"units": result, "note": "Known unit names only. Missing units are not proof that an equivalent service is absent. openvpn@server is a service observation, not tunnel/client health."}
    if op == "inventory":
        cursor = args["cursor"]
        if not isinstance(cursor,str) or not re.fullmatch(r"[0-9]{1,20}",cursor):
            raise ValueError("invalid cursor")
        raw = run(["redis-cli", "--raw", "SCAN", cursor, "MATCH", "host:mac:*", "COUNT", "32"]).splitlines()
        if not raw or not re.fullmatch(r"[0-9]{1,20}",raw[0]) or len(raw)>257:
            raise Unsupported("unknown SCAN shape or page too large")
        macs=[]
        for key in raw[1:]:
            if not key:
                continue
            if not re.fullmatch(r"host:mac:(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", key):
                raise Unsupported("unknown device key schema")
            macs.append(key[9:].upper())
        return {"cursor":raw[0], "macs":macs, "note":"SCAN may return duplicates or empty nonterminal pages; stop only at cursor 0. No names or hash dumps."}
    if op == "device_policy":
        mac=args["mac"].upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}",mac):
            raise ValueError("invalid mac")
        raw=run(["redis-cli","--raw","HGET","policy:mac:"+mac,"vpnClient"]).strip()
        if not raw:
            return {"explicit_policy":None,"effective_path":"unknown; inherited policies not resolved"}
        policy=json.loads(raw)
        if not isinstance(policy,dict) or (policy.get("state") is not None and type(policy.get("state")) is not bool):
            raise Unsupported("unknown policy schema")
        out={"state":policy.get("state")}
        if policy.get("profileId") is not None:
            out["profile_id"]=atom(policy["profileId"])
        return {"explicit_policy":out,"effective_path":"unknown; inherited policies and kernel marks not resolved"}
    if op == "vpn_interfaces":
        rows=network("addresses")["rows"]
        return {"interfaces":[r for r in rows if re.match(r"^(vpn_|tun|tap|wg)",r.get("ifname",""))], "note":"Interface naming heuristic only, not an inventory of configured VPN profiles."}
    if op == "traffic":
        rows=json.loads(run(["ip","-j","-s","link","show"]))
        result=[]
        for row in rows[:256]:
            stats=row.get("stats64",row.get("stats"))
            if not isinstance(stats,dict):
                raise Unsupported("missing interface statistics")
            item={"interface":atom(row["ifname"])}
            for direction in ("rx","tx"):
                item[direction]={k:int(stats[direction][k]) for k in ("bytes","packets","errors","dropped")}
            result.append(item)
        return {"interfaces":result,"truncated":len(rows)>256,"note":"Cumulative kernel counters; reset on interface recreation. Not Firewalla per-device usage or a billing total."}
    if op == "alarm_count":
        seconds=args["seconds"]
        if type(seconds) is not int or not 60<=seconds<=604800:
            raise ValueError("invalid time window")
        kind=run(["redis-cli","--raw","TYPE","alarm_active"]).strip()
        if kind!="zset":
            raise Unsupported("active alarm index absent or changed")
        now=int(time.time())
        count=run(["redis-cli","--raw","ZCOUNT","alarm_active",str(now-seconds),str(now)]).strip()
        if not count.isdigit():
            raise Unsupported("unknown count")
        return {"active_alarm_count":int(count),"start_epoch":now-seconds,"end_epoch":now,"note":"Active-index score window only; not archived alarms or alarm descriptions."}
    if op == "dns_config":
        with open("/etc/resolv.conf") as f:
            raw=f.read(8193)
        if len(raw)>8192:
            raise Unsupported("resolver config oversized")
        return {"nameservers":[ip(line.split()[1]) for line in raw.splitlines() if line.strip().startswith("nameserver ")][:16],"note":"System resolver only; split DNS, DNS rules, encrypted DNS and search domains omitted."}
    if op == "conntrack":
        address=ip(args["address"])
        raw=run(["sudo","-n","conntrack","-L","-s",address,"-o","extended"])
        result=[]
        for line in raw.splitlines():
            fields=line.split()
            tuples=[]
            for field in fields:
                if "=" not in field:
                    continue
                k,v=field.split("=",1)
                if k in ("src","dst"):
                    tuples.append({k:ip(v)})
                elif k in ("sport","dport"):
                    tuples.append({k:port(int(v))})
            if tuples:
                result.append({"tuples_in_kernel_order":tuples})
        return {"connections":result[:128],"truncated":len(result)>128,"note":"Original/reply address/port metadata for one source. No payload, application attribution or NAT policy verdict."}
    if op == "capabilities":
        return {"utilities": {x: shutil.which(x) is not None for x in ["python3", "ip", "ss", "redis-cli", "iptables", "ipset", "conntrack", "getent", "nc"]},
                "adapters": "schema-probed on each call; no firmware version is assumed supported"}
    if op == "health":
        with open("/proc/uptime") as f:
            uptime = float(f.read(128).split()[0])
        with open("/proc/meminfo") as f:
            mem = dict(re.findall(r"^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)", f.read(8192), re.M))
        return {"uptime_seconds": uptime, "load_average": list(os.getloadavg()), "memory_kib": {k:int(v) for k,v in mem.items()}}
    if op == "network":
        return network(args["kind"])
    if op == "device":
        mac = args["mac"].upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", mac):
            raise ValueError("invalid mac")
        address = run(["redis-cli", "--raw", "HGET", "host:mac:"+mac, "ipv4Addr"]).strip()
        if not address:
            raise Unsupported("device absent or unsupported schema")
        return {"mac": mac, "ipv4": ip(address), "note": "Known MAC lookup; no device names or full host hashes."}
    if op == "vpn":
        interface = atom(args["interface"])
        addresses = network("addresses")["rows"]
        found = [r for r in addresses if r.get("ifname")==interface]
        if not found:
            raise Unsupported("interface absent")
        return {"interface": found, "note": "Interface state only; does not establish VPN provider health or device selection."}
    if op == "mappings":
        return mappings()
    if op == "firewall":
        if args["table"] not in ("filter", "nat", "mangle"):
            raise ValueError("invalid table")
        return firewall(args["table"])
    if op == "ipsets":
        rows = run(["sudo", "-n", "ipset", "list", "-name"]).splitlines()
        return {"names": [atom(x) for x in rows[:256]], "truncated": len(rows)>256}
    if op == "connections":
        # ss socket summary contains counts, not traffic or payload.
        raw = run(["ss", "-s"])
        total = re.search(r"Total:\s+(\d+)", raw)
        if not total:
            raise Unsupported("unknown ss schema")
        return {"local_socket_count": int(total.group(1)), "note": "Router-local sockets only; not forwarded conntrack/NAT sessions."}
    if op == "tcp":
        target, number = ip(args["address"]), port(args["port"])
        # nc emits no payload, and stderr is discarded. Failure remains inconclusive.
        try:
            run(["nc", "-z", "-w", "3", target, str(number)], 4)
            return {"outcome": "connected", "meaning": "TCP handshake succeeded from this site; application protocol not tested."}
        except Unsupported:
            return {"outcome": "inconclusive", "meaning": "Timeout, rejection, missing utility, or path failure; not proof of global closure."}
    if op == "dns":
        name = args["name"]
        if len(name)>253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", s) for s in name.split(".")):
            raise ValueError("invalid DNS name")
        raw = run(["getent", "ahosts", name])
        return {"addresses": sorted(set(ip(line.split()[0]) for line in raw.splitlines()))[:32], "resolver": "router system resolver"}
    raise Unsupported("adapter not implemented")


def execute(op, args):
    try:
        return {"status": "ok", "data": dispatch(op, args)}
    except (Unsupported, ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired):
        return {"status": "unsupported", "reason": "Unavailable utility, permission, output/time limit, or unrecognized schema. No raw output returned."}

if __name__ == "__main__":
    request = json.loads(sys.argv[1])
    print(json.dumps(execute(request["operation"], request["arguments"])))
