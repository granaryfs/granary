#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Construct retained-submission bytes from the format tables, not its codec.

Only hashing calls Rust: the helper links the existing BLAKE3 dependency.
Run from the repository root. The output manifest pins each refusal's rule.
"""
from pathlib import Path
import json
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
metadata = json.loads(subprocess.run(
    ['cargo', 'metadata', '--format-version', '1', '--no-deps'],
    cwd=ROOT, check=True, capture_output=True, text=True).stdout)
target = Path(metadata['target_directory'])
subprocess.run(['cargo', 'build', '--offline', '-p', 'granary-core'], cwd=ROOT, check=True)
helper = target / 'retained-vector-hash.rs'
helper.parent.mkdir(parents=True, exist_ok=True)
helper.write_text('''// SPDX-License-Identifier: Apache-2.0
use std::io::{Read, Write};
fn main() {
    let mut b = Vec::new(); std::io::stdin().read_to_end(&mut b).unwrap();
    let (tag, bytes) = b.split_at(1);
    let digest = if tag[0] == 0 { *blake3::hash(bytes).as_bytes() }
    else if tag[0] == 1 { blake3::derive_key("granary retained-submission v1", bytes) }
    else { blake3::derive_key("granary retained-submission scope v1", bytes) };
    std::io::stdout().write_all(&digest).unwrap();
}
''')
deps = target / 'debug/deps'
libraries = sorted(deps.glob('libblake3-*.rlib'))
if not libraries:
    raise SystemExit(f'BLAKE3 library not found: {deps}/libblake3-*.rlib')
rlib = libraries[0]
exe = target / 'retained-vector-hash'
subprocess.run(['rustc', '--edition=2024', str(helper), '--extern', f'blake3={rlib}', '-L', f'dependency={deps}', '-o', str(exe)], check=True)
def hash_bytes(b, derive=False):
    return subprocess.run([str(exe)], input=bytes([derive])+bytes(b), stdout=subprocess.PIPE, check=True).stdout

def u8(n): return struct.pack('>B', n)
def u16(n): return struct.pack('>H', n)
def u32(n): return struct.pack('>I', n)
def u64(n): return struct.pack('>Q', n)
def lp(b, width=1): return len(b).to_bytes(width, 'big') + b
def gid(b): return b'\x01' + hash_bytes(b)
def fix(body):
    b = bytearray(body)
    b[10:14] = u32(len(b) + 32)
    return bytes(b) + hash_bytes(b, True)

def root(seq=1, volume=b'vol', manifest=0x44, stamp=1):
    return (b'GRANARY\0\x09\x01' + lp(volume) + u64(seq) +
            (b'\0' if seq == 1 else b'\x01\x01' + bytes([0x77])*32) +
            bytes([0x33])*16 + u64(1) + u64(stamp) + u32(0) + lp(b'test') +
            b'\x01' + bytes([manifest])*32 + b'\0' +
            b'\x01' + bytes([0x55])*32 + b'\x01' + bytes([0x66])*32 +
            b'\x01' + bytes([0x88])*32 + b'\x01' + u16(64) + bytes([0x99])*64)

R = root()
E = bytes([0x11])*16
O = bytes([0x22])*16

def record(phase=1, count=1, current=True, roles=None, receipt=False, response=False,
           started=1, proved=0, answered=0, decision=False, number_start=1):
    b = bytearray(); offsets = {}
    def put(name, value): offsets[name] = len(b); b.extend(value)
    put('magic', b'GRNSUBMS'); put('version', u16(1)); put('length', u32(0))
    put('generation', u64(1)); put('publication', bytes(range(16)))
    put('base', lp(b'https://example.test/', 2)); put('pins', b'\x02'+bytes([1])*32+bytes([2])*32)
    put('context', lp(b'operator')); put('volume', lp(b'vol'))
    put('writer', bytes([0x33])*16); put('policy', b'\0'); put('initial', lp(R, 4))
    put('current', u8(current)+(E+O if current else b'')); put('count', u16(count))
    for n in range(count):
        prefix = f'c{n}-'
        put(prefix+'number', u64(n + number_start))
        role = roles[n] if roles else (1 if n == 0 else 2)
        put(prefix+'role', u8(role))
        put(prefix+'epoch', E if role != 3 else bytes([0x40+n])*16)
        put(prefix+'operation', O if role != 3 else bytes([0x60+n])*16)
        put(prefix+'seq', u64(1)); put(prefix+'id', gid(R)); put(prefix+'root', lp(R, 4))
        put(prefix+'started', u64(started)); put(prefix+'proved', u64(proved))
        put(prefix+'answered', u64(answered)); put(prefix+'decision', u8(decision))
    put('phase', u8(phase))
    if phase == 2: put('await-candidate', u64(1)); put('await-attempt', u64(started))
    if phase == 4: put('new-epoch', bytes([0x90])*16)
    if phase in (5, 6):
        put('cycle', u64(1)); put('probe-seq', u64(1)); put('reason', u8(0 if phase == 5 else 2))
    if phase == 7:
        put('done-seq', u64(1)); put('done-id', gid(R)); put('done-root', lp(R, 4))
        put('receipt', u8(receipt))
        if receipt:
            put('receipt-epoch', E); put('entry', u64(7)); put('receipt-seq', u64(1)); put('receipt-id', gid(R))
    put('response', u8(response))
    if response:
        put('response-candidate', u64(1)); put('response-attempt', u64(answered))
        put('status', u16(429)); put('token', lp(b'rate-limited')); put('answer', lp(b'', 2))
    return bytes(b), offsets

vectors = ROOT / 'crates/granary-core/tests/vectors/retained-submission'
corpus = ROOT / 'crates/granary-core/fuzz/corpus/retained_submission_decode'
vectors.mkdir(parents=True, exist_ok=True); corpus.mkdir(parents=True, exist_ok=True)

def v2(body, exemptions=0):
    return body[:8] + u16(2) + body[10:] + u16(exemptions)

def golden(name, body):
    b = fix(body)
    (vectors / f'{name}.bin').write_bytes(b)
    (vectors / f'{name}.hash').write_text('blake3:'+hash_bytes(b).hex()+'\n')
    (corpus / name).write_bytes(b)

samples = {
    'ready': {}, 'awaiting': {'phase':2}, 'rebase':{'phase':3},
    'epoch-recovery': {'phase':4,'current':False,'roles':[3]},
    'probe-started': {'phase':5}, 'unresolved':{'phase':6},
    'complete-chain': {'phase':7,'current':False},
    'complete-receipt': {'phase':7,'current':False,'receipt':True},
    'response': {'response':True,'answered':1,'proved':1},
    'catalogue': {'count':3,'roles':[1,2,3]},
    'capacity': {'count':128},
}
for name, kwargs in samples.items():
    body, _ = record(**kwargs)
    golden(name, body)
    golden(f'v2-{name}', v2(body))
# Boundary scope and a nonempty embedded answer, still assembled by layout.
for name in ['scope-bounds', 'response-answer', 'empty-catalogue', 'initial-last-candidate', 'rebased-manifest']:
    if name == 'rebased-manifest':
        body, off = record(number_start=2)
        body = bytearray(body)
        rebased = root(seq=2, manifest=0x45)
        body[off['c0-root']:off['c0-started']] = lp(rebased, 4)
        body[off['c0-id']:off['c0-root']] = gid(rebased)
        body[off['c0-seq']:off['c0-id']] = u64(2)
    elif name == 'initial-last-candidate':
        body, off = record()
        body = bytearray(body)
        body[off['initial']:off['current']] = lp(root(seq=2**64-3), 4)
    elif name == 'empty-catalogue':
        body, off = record(phase=4, count=0, current=False)
    elif name == 'response-answer':
        body, off = record(response=True, answered=1, decision=True)
        body = bytearray(body)
        body[off['answer']:] = lp(b'GRNANSWR' + u16(1) + b'\x03' + E + u64(7) + gid(R), 2)
        body[off['status']:off['token']] = u16(202)
        body[off['token']:off['answer']] = lp(b'')
    else:
        body, off = record()
        body = bytearray(body)
        body[off['policy']] = 12
        body[off['context']:off['volume']] = lp(bytes([0x61])*255)
        body[off['pins']:off['context']] = u8(8)+b''.join(bytes([i])*32 for i in range(8))
        body[off['base']:off['pins']] = lp(bytes([0x62])*8192, 2)
    golden(name, body)
    golden(f'v2-{name}', v2(body))
body, _ = record(response=True, started=38, answered=38, proved=1)
golden('v2-exemptions', v2(body, 37))
bound_body, _ = record(response=True, started=1025, answered=1025, proved=1)
golden('v2-exemptions-bound', v2(bound_body, 1024))
(vectors/'scope.hash').write_text(hash_bytes(lp(b'https://example.test/',2)+lp(b'operator'),2).hex()+'\n')
rejects = []
def reject(name, rule, field=None, replacement=None, kwargs=None, raw=None):
    body, offsets = record(**(kwargs or {}))
    body = bytearray(body)
    if field is not None:
        start = offsets[field]; body[start:start+len(replacement)] = replacement
    b = raw if raw is not None else fix(body)
    (vectors / ('reject-'+name)).write_bytes(b)
    (corpus / ('reject-'+name)).write_bytes(b)
    rejects.append((name,rule))
reject('magic','magic','magic',b'X')
reject('version','version 3','version',u16(3))
reject('exemptions-bound', 'unavailable exemptions', raw=fix(v2(body, 1025)))
reject('exemptions-truncated', 'truncated', raw=fix(v2(body)[:-1]))
reject('v1-trailing-exemptions', 'trailing', raw=fix(body + u16(0)))
reject('generation','generation','generation',u64(0))
reject('base-empty','authority base length','base',u16(0)) # Rebuild to keep subsequent fields aligned below.
body, off = record(); b=bytearray(body); start=off['base']; del b[start+2:start+2+len(b'https://example.test/')]; b[start:start+2]=u16(0)
reject('base-empty','authority base length',raw=fix(b))
reject('base-cap','field length','base',u16(8193))
reject('pins-cap','pin count','pins',u8(9))
reject('pins-order','pin order','pins',u8(2)+bytes([2])*64)
body, off=record(); b=bytearray(body); i=off['context']; del b[i+1:i+9]; b[i]=0
reject('context-empty','context length',raw=fix(b))
reject('volume','volume','volume',lp(b'../'))
reject('volume-cap','field length','volume',u8(64))
reject('policy','preparation policy','policy',u8(13))
reject('initial-cap','field length','initial',u32(65537))
reject('initial-malformed','magic','initial',u32(len(R))+b'X')
for name, seq in [('zero', 0), ('reserved', 2**64-2), ('maximum', 2**64-1)]:
    body, off = record(); body = bytearray(body)
    body[off['initial']:off['current']] = lp(root(seq=seq), 4)
    reject('initial-seq-'+name, 'root seq', raw=fix(body))
reject('current-bool','boolean','current',u8(2))
reject('count','candidate count','count',u16(129))
reject('number-zero','candidate order','c0-number',u64(0))
reject('number-order','candidate order','c1-number',u64(1),{'count':2})
reject('role','role','c0-role',u8(4))
reject('active-count','active cardinality','c1-role',u8(1),{'count':2})
reject('current-epoch','current identity','c0-epoch',bytes([0x12])*16)
reject('current-operation','current identity','c0-operation',bytes([0x12])*16)
reject('retired-epoch','retired epoch','c0-role',u8(3))
reject('operation-reuse','operation crosses epochs','c1-operation',O,{'count':2,'roles':[1,3]})
reject('seq-binding','candidate binding','c0-seq',u64(2))
reject('id-binding','candidate binding','c0-id',b'\x01'+bytes([0])*32)
reject('id-tag','grain id','c0-id',u8(255))
reject('candidate-root-cap','field length','c0-root',u32(65537))
reject('candidate-root-malformed','magic','c0-root',u32(len(R))+b'X')
for name, new, rule in [('root-volume',root(volume=b'bad'),'root volume'),('root-ceiling',root(seq=2**64-1),'root seq'),('manifest',root(manifest=0x45),'frozen manifest')]:
    body, off=record(); b=bytearray(body); i=off['c0-root']; b[i:i+4+len(R)]=lp(new,4); b[off['c0-id']:off['c0-id']+33]=gid(new)
    if name=='root-ceiling': b[off['c0-seq']:off['c0-seq']+8]=u64(2**64-1)
    reject(name,rule,raw=fix(b))
reject('proved','attempt counters','c0-proved',u64(1))
reject('answered','attempt counters','c0-answered',u64(2))
reject('decision-unstarted','attempt counters','c0-decision',u8(1),{'started':0})
reject('decision-bool','boolean','c0-decision',u8(2))
reject('phase','phase tag','phase',u8(8))
reject('ready-empty','ready phase',kwargs={'count':0})
reject('await-reference','candidate reference','await-candidate',u64(2),{'phase':2})
reject('await-attempt','awaiting phase','await-attempt',u64(0),{'phase':2})
reject('await-role','awaiting phase','c0-role',u8(2),{'phase':2})
reject('rebase-current','rebase phase',kwargs={'phase':3,'count':0,'current':False})
reject('epoch-current','epoch recovery phase',kwargs={'phase':4})
reject('probe-cycle','probe position','cycle',u64(0),{'phase':5})
reject('probe-seq','probe position','probe-seq',u64(2),{'phase':5})
reject('probe-start-reason','probe reason','reason',u8(1),{'phase':5})
reject('unresolved-reason','probe reason','reason',u8(0),{'phase':6})
reject('reason-tag','probe reason tag','reason',u8(7),{'phase':6})
reject('complete-current','complete current identity',kwargs={'phase':7})
for name, field, value in [('seq','done-seq',u64(2)),('id','done-id',b'\x01'+bytes(32)),('root','done-root',lp(root(stamp=2),4))]:
    reject('completion-'+name,'completion binding',field,value,{'phase':7,'current':False})
for name, field, value in [('entry','entry',u64(0)),('epoch','receipt-epoch',bytes(16)),('seq','receipt-seq',u64(2)),('id','receipt-id',b'\x01'+bytes(32))]:
    reject('receipt-'+name,'completion receipt',field,value,{'phase':7,'current':False,'receipt':True})
reject('receipt-bool','boolean','receipt',u8(2),{'phase':7,'current':False})
reject('response-bool','boolean','response',u8(2))
for name, field, value, rule in [('reference','response-candidate',u64(2),'candidate reference'),('attempt','response-attempt',u64(0),'response attempt'),('status','status',u16(600),'response status'),('token-cap','token',u8(65),'field length'),('token','token',lp(b'RATE-LIMITED'),'response token'),('answer-cap','answer',u16(154),'field length')]:
    reject('response-'+name,rule,field,value,{'response':True,'answered':1})
body, off=record(response=True,answered=1); b=bytearray(body); b[off['answer']:]=lp(b'garbage',2)
reject('answer-malformed','answer bytes',raw=fix(b))
body,_=record()
reject('self-check','check mismatch',raw=fix(body)[:-1]+bytes([fix(body)[-1]^1]))
reject('total-length','total length',raw=fix(body)+b'\0')
reject('trailing','trailing bytes',raw=fix(body+b'\0'))
reject('truncated','truncated',raw=b'GRNSUBMS')
for field in ['initial', 'c0-root']:
    body, off = record(); body = bytearray(body); i=off[field]
    body[i:i+4+len(R)] = u32(0)
    reject(field+'-empty', 'root length', raw=fix(body))
for name, initial_seq, candidate_seq in [('equal', 1, 1), ('earlier', 3, 2)]:
    body, off = record(number_start=2)
    body = bytearray(body)
    rebased = root(seq=candidate_seq, manifest=0x45)
    body[off['c0-root']:off['c0-started']] = lp(rebased, 4)
    body[off['c0-id']:off['c0-root']] = gid(rebased)
    body[off['c0-seq']:off['c0-id']] = u64(candidate_seq)
    body[off['initial']:off['current']] = lp(root(seq=initial_seq), 4)
    reject('rebase-seq-'+name, 'rebase sequence', raw=fix(body))
body, off = record()
body = bytearray(body)
rebased = root(seq=2, manifest=0x45)
body[off['c0-root']:off['c0-started']] = lp(rebased, 4)
body[off['c0-id']:off['c0-root']] = gid(rebased)
body[off['c0-seq']:off['c0-id']] = u64(2)
reject('first-candidate-merged-manifest', 'frozen manifest', raw=fix(body))
reject('status-low','response status','status',u16(99),{'response':True,'answered':1})
reject('pins-reversed','pin order','pins',u8(2)+bytes([2])*32+bytes([1])*32)
# Deduplicate repeated names while retaining exact rule expectations.
(vectors/'rejects.tsv').write_text(''.join(n+'\t'+r+'\n' for n,r in dict(rejects).items()))
print(f'{2 * (len(samples) + 5) + 2} golden vectors; {len(dict(rejects))} reject seeds')
