"""Pinned router-local capture helper. Never emits raw packet bytes or stderr.

Run by a separately approved fixed SSH gate under a bounded root timeout. PCAP
exists only in process memory; stdout is allowlisted NDJSON metadata events.
"""
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time


def validate(spec):
    if not isinstance(spec,dict) or set(spec)!={'interface','address','device','protocol','port','duration','packets'}:raise ValueError('shape')
    if not isinstance(spec['interface'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',spec['interface']) or spec['interface']=='any':raise ValueError('interface')
    if bool(spec['address'])==bool(spec['device']):raise ValueError('one target required')
    if spec['address']:
        address=ipaddress.ip_address(spec['address'])
        if '%' in spec['address'] or address.is_unspecified or address.is_multicast:raise ValueError('address')
        spec['address']=str(address)
    if spec['device'] and not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',spec['device']):raise ValueError('device')
    if spec['protocol'] not in ('tcp','udp','icmp'):raise ValueError('protocol')
    if spec['port'] is not None and (type(spec['port']) is not int or not 1<=spec['port']<=65535 or spec['protocol']=='icmp'):raise ValueError('port')
    if type(spec['duration']) is not int or not 1<=spec['duration']<=15:raise ValueError('duration')
    if type(spec['packets']) is not int or not 1<=spec['packets']<=100:raise ValueError('packets')
    return spec


def command(spec):
    validate(spec)
    target=['host',spec['address']] if spec['address'] else ['ether','host',spec['device']]
    protocol=['(', 'icmp','or','icmp6',')'] if spec['protocol']=='icmp' else [spec['protocol']]
    expression=['(']+target+[')','and']+protocol
    if spec['port'] is not None:expression+=['and','port',str(spec['port'])]
    return ['/usr/bin/tcpdump','-n','-U','-s','96','-c',str(spec['packets']),'-i',spec['interface'],'-w','-',' '.join(expression)]


def packet_metadata(data,linktype,timestamp,wire_length):
    offset=0;ethertype=None
    if linktype==1:
        if len(data)<14:return None
        offset=14;ethertype=struct.unpack('!H',data[12:14])[0]
        for _ in range(4):
            if ethertype not in (0x8100,0x88a8):break
            if len(data)<offset+4:return None
            ethertype=struct.unpack('!H',data[offset+2:offset+4])[0];offset+=4
    elif linktype==113:
        if len(data)<16:return None
        offset=16;ethertype=struct.unpack('!H',data[14:16])[0]
    elif linktype==276:
        if len(data)<20:return None
        offset=20;ethertype=struct.unpack('!H',data[:2])[0]
    elif linktype not in (12,101,228,229):return None
    if len(data)<=offset:return None
    version=data[offset]>>4;fragment=False
    if version==4 and ethertype in (None,0x800):
        if len(data)<offset+20:return None
        header=(data[offset]&15)*4
        if header<20 or len(data)<offset+header:return None
        total=struct.unpack('!H',data[offset+2:offset+4])[0]
        if total<header:return None
        data=data[:min(len(data),offset+total)]
        proto=data[offset+9];src=str(ipaddress.ip_address(data[offset+12:offset+16]));dst=str(ipaddress.ip_address(data[offset+16:offset+20]))
        fragment=bool(struct.unpack('!H',data[offset+6:offset+8])[0]&0x1fff);offset+=header
    elif version==6 and ethertype in (None,0x86dd):
        if len(data)<offset+40:return None
        payload=struct.unpack('!H',data[offset+4:offset+6])[0]
        if payload==0:return None
        data=data[:min(len(data),offset+40+payload)]
        proto=data[offset+6];src=str(ipaddress.ip_address(data[offset+8:offset+24]));dst=str(ipaddress.ip_address(data[offset+24:offset+40]));offset+=40
        for _ in range(4):
            if proto not in (0,43,44,51,60):break
            if len(data)<offset+8:return None
            nxt=data[offset]
            if proto==44:fragment=bool(struct.unpack('!H',data[offset+2:offset+4])[0]&0xfff8);length=8
            elif proto==51:length=(data[offset+1]+2)*4
            else:length=(data[offset+1]+1)*8
            if len(data)<offset+length:return None
            offset+=length;proto=nxt
    else:return None
    row={'timestamp_epoch':timestamp,'source':src,'destination':dst,'ip_version':version,
         'protocol':{6:'tcp',17:'udp',1:'icmp',58:'icmp6'}.get(proto,'other'),
         'source_port':None,'destination_port':None,'tcp_flags':[],
         'wire_length':wire_length,'captured_header_bytes':len(data),'fragment_without_ports':fragment}
    if proto in (6,17) and not fragment:
        if len(data)<offset+(20 if proto==6 else 8):return None
        row['source_port'],row['destination_port']=struct.unpack('!HH',data[offset:offset+4])
        if proto==6:
            if len(data)<offset+14:return None
            row['tcp_flags']=[name for bit,name in enumerate(('FIN','SYN','RST','PSH','ACK','URG','ECE','CWR')) if data[offset+13]&(1<<bit)]
    return row


class Parser:
    def __init__(self,maximum=100):self.buffer=bytearray();self.endian=None;self.linktype=None;self.scale=1e6;self.rows=[];self.skipped=0;self.maximum=maximum;self.seen=0;self.truncated=False
    def feed(self,data):
        self.buffer.extend(data)
        if len(self.buffer)>262144:raise ValueError('capture input bound')
        if self.endian is None:
            if len(self.buffer)<24:return
            magic=bytes(self.buffer[:4]);formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
            if magic not in formats:raise ValueError('pcap format')
            self.endian,self.scale=formats[magic];major,minor,_,_,snap,self.linktype=struct.unpack(self.endian+'HHIIII',self.buffer[4:24]);del self.buffer[:24]
            if (major,minor)!=(2,4) or snap>96 or self.linktype not in (1,12,101,113,228,229,276):raise ValueError('unsupported capture header')
        while len(self.buffer)>=16:
            sec,frac,size,wire=struct.unpack(self.endian+'IIII',self.buffer[:16])
            if size>96 or size>wire or frac>=self.scale:raise ValueError('record bound')
            if len(self.buffer)<16+size:return
            packet=bytes(self.buffer[16:16+size]);del self.buffer[:16+size];self.seen+=1
            row=packet_metadata(packet,self.linktype,sec+frac/self.scale,wire)
            if row is None:self.skipped+=1
            elif len(self.rows)<self.maximum:self.rows.append(row)
            else:self.truncated=True


def statistics(text):
    result={'captured':None,'received_by_filter':None,'dropped_by_kernel':None}
    for key,label in [('captured','packets? captured'),('received_by_filter','packets? received by filter'),('dropped_by_kernel','packets? dropped by kernel')]:
        match=re.search(r'(?m)^(\d+) '+label+r'\s*$',text)
        if match:result[key]=int(match.group(1))
    return result


def emit(value):
    print(json.dumps(value,separators=(',',':')),flush=True)


def capture(spec,send=emit):
    validate(spec)
    if spec['interface'] not in {name for _,name in socket.if_nameindex()}:raise ValueError('interface absent')
    parser=Parser(spec['packets']);stderr=bytearray();ready=False;ready_at=None;reason='duration_limit';proc=None
    def stop(*_):raise InterruptedError('cancelled')
    old={s:signal.signal(s,stop) for s in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT)}
    try:
        proc=subprocess.Popen(command(spec),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,'pcap');selector.register(proc.stderr,selectors.EVENT_READ,'stderr');selector.register(sys.stdin,selectors.EVENT_READ,'cancel')
            end=time.monotonic()+spec['duration'];startup=time.monotonic()+3
            while time.monotonic()<end:
                if not ready and time.monotonic()>startup:reason='startup_timeout';break
                for key,_ in selector.select(.1):
                    raw=os.read(key.fd,65536)
                    if key.data=='cancel':reason='cancelled';raise InterruptedError()
                    if not raw:
                        selector.unregister(key.fileobj);continue
                    if key.data=='pcap':parser.feed(raw)
                    else:
                        stderr.extend(raw)
                        if len(stderr)>8192:reason='stderr_bound';raise InterruptedError()
                        if not ready and b'listening on ' in stderr:
                            ready=True;ready_at=time.time();send({'event':'ready','started_at':ready_at,'duration_limit':spec['duration'],'packet_limit':spec['packets']})
                if proc.poll() is not None:reason='packet_limit' if parser.seen>=spec['packets'] else 'process_exit';break
    except InterruptedError:
        if reason=='duration_limit':reason='cancelled'
    except (ValueError,OSError):reason='capture_error'
    finally:
        if proc:
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGINT)
                except ProcessLookupError:pass
            try:remaining,errors=proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);remaining,errors=proc.communicate(timeout=1);reason='forced_cleanup'
            try:parser.feed(remaining)
            except ValueError:reason='parse_error'
            stderr.extend(errors[:max(0,8192-len(stderr))])
        for s,handler in old.items():signal.signal(s,handler)
    if ready and reason=='process_exit' and proc and proc.returncode!=0:reason='capture_error'
    diagnostic=stderr.decode('ascii','replace');stats=statistics(diagnostic)
    if not ready:
        reason='permission_denied' if re.search('permission denied|not permitted',diagnostic,re.I) else 'startup_failed'
    send({'event':'completed','status':'completed' if ready and reason in ('duration_limit','packet_limit','process_exit') else reason,
          'ready':ready,'started_at':ready_at,'ended_at':time.time(),'stop_reason':reason,'metadata':parser.rows,'records_seen':parser.seen,'unparsed_records':parser.skipped,
          'truncated':parser.truncated or bool(parser.buffer),'statistics':stats,
          'meaning':'Only packets observed at this scoped interface during this interval. Zero records is not proof of no traffic or a globally closed port.'})


def main():
    try:
        line=sys.stdin.buffer.readline(4097)
        if len(line)>4096:raise ValueError('request bound')
        capture(json.loads(line))
    except Exception:emit({'event':'completed','status':'invalid_or_unavailable','ready':False,'metadata':[]})

if __name__=='__main__':main()
