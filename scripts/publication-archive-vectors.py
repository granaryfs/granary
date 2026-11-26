#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Construct archive namespace vectors from independent retained fixtures.

Only generation/publication identity and the exact-byte check change. A Rust
helper links the existing BLAKE3 library; the retained codec is never invoked.
"""
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'target'
subprocess.run(['cargo', 'build', '--offline', '-p', 'granary-core'], cwd=ROOT, check=True)
deps = TARGET / 'debug/deps'
rlibs = sorted(deps.glob('libblake3-*.rlib'))
if not rlibs:
    raise SystemExit('build granary-core into target/ before constructing vectors')
helper = TARGET / 'archive-vector-hash.rs'
helper.write_text('''// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
use std::io::{Read, Write};
fn main() {
    let mut b = Vec::new(); std::io::stdin().read_to_end(&mut b).unwrap();
    let (tag, bytes) = b.split_at(1);
    let hash = match tag[0] {
        0 => *blake3::hash(bytes).as_bytes(),
        1 => blake3::derive_key("granary retained-submission v1", bytes),
        _ => blake3::derive_key("granary retained-submission scope v1", bytes),
    };
    std::io::stdout().write_all(&hash).unwrap();
}
''')
exe = TARGET / 'archive-vector-hash'
subprocess.run(['rustc', '--edition=2024', str(helper), '--extern', f'blake3={rlibs[0]}', '-L', f'dependency={deps}', '-o', str(exe)], check=True)
def digest(data, tag=0):
    return subprocess.run([str(exe)], input=bytes([tag])+bytes(data), stdout=subprocess.PIPE, check=True).stdout

def checked(body):
    return bytes(body)+digest(body, 1)
source = ROOT / 'crates/granary-core/tests/vectors/retained-submission'
out = ROOT / 'crates/granary-client/tests/vectors/publication-archives'
out.mkdir(parents=True, exist_ok=True)
manifest = ['# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>', '# SPDX-License-Identifier: Apache-2.0', '# vector\tfull-file-hash\tscope-digest\tvolume\tarchive-name\tdefault-load']
for name in ['catalogue', 'capacity', 'awaiting', 'response-answer', 'max-generation',
             'v2-catalogue', 'v2-capacity', 'v2-awaiting', 'v2-response-answer']:
    body = bytearray((source / ('ready.bin' if name == 'max-generation' else name+'.bin')).read_bytes()[:-32])
    body[14:22] = struct.pack('>Q', 2**64-1 if name == 'max-generation' else 2)
    data = checked(body)
    (out / (name+'.bin')).write_bytes(data)
    base_length = int.from_bytes(body[38:40], 'big')
    base = body[38:40+base_length]
    pins = 40+base_length
    context = pins+1+32*body[pins]
    context_bytes = body[context:context+1+body[context]]
    scope = digest(base+context_bytes, 2).hex()
    archive_name = 'vol.abandoned-'+body[22:38].hex()+'.sub'
    manifest.append('\t'.join([name,'blake3:'+digest(data).hex(),scope,'vol',archive_name,'Abandoned']))
(out/'namespace.tsv').write_text('\n'.join(manifest)+'\n')
body = bytearray((source / 'v2-ready.bin').read_bytes()[:-32])
body[14:22] = struct.pack('>Q', 2)
# Ready, with no response. The last 29 bytes start at the candidate's
# started counter, followed by evidence, phase, response presence and count.
body[-29:-21] = struct.pack('>Q', 0)
proof = checked(body)
(out/'proof-no-write-v2.bin').write_bytes(proof)
(out/'proof-no-write-v2.hash').write_text('blake3:'+digest(proof).hex()+'\n')
body = bytearray((out/'catalogue.bin').read_bytes()[:-32])
body[22:38] = b'\xff'*16
(out/'different-live.bin').write_bytes(checked(body))
body = bytearray((out/'catalogue.bin').read_bytes()[:-32])
body[14:22] = struct.pack('>Q', 3)
(out/'conflicting-live.bin').write_bytes(checked(body))
(out/'states.tsv').write_text('''# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# archive-vector\tlive-vector\tselection\tretry
catalogue\t-\tAbandoned\tidempotent
catalogue\tdifferent-live\tLive\tkeep-live
catalogue\tcatalogue\tConflict\tunlink-live
catalogue\tconflicting-live\tConflict\trefuse
''')
(out/'rejects.tsv').write_text('''# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
# fixture or filesystem condition\tguard
archive-name/reject-*\treserved namespace grammar
retained-submission/reject-pins-order\tcanonical pins
corrupt\texact-byte check and strict decode
oversized\tcomplete file cap
wrong-scope\texact scope digest path binding
wrong-volume\tvolume path binding
wrong-id\tpublication identity path binding
complete\tterminal completion
symlink\tno-follow regular-file custody
hardlink\tsole-link custody except exact A+L inode retry
nonregular\tregular-file custody
mode\t0600 permissions
owner\teffective uid ownership
acl\tgranting descriptor ACL refusal on macOS
''')
