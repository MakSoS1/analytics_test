"""Explicit availability downgrade, never invent facts absent from the office source."""
from pathlib import Path
import struct
import payload_sidecar as pay


def availability_version(path):
    with Path(path).open('rb') as f:h=f.read(8)
    if len(h)!=8 or h[:4]!=b'OPAY':raise ValueError('not an OPAY sidecar')
    return h[4]


def downgrade(path,target):
    path=Path(path);blob=path.read_bytes();version=availability_version(path)
    if target==version:return
    if version!=4 or target not in (1,3):raise ValueError('unsupported availability migration')
    # Validate original records through the production decoder first.
    list(pay.read_sidecar(path))
    out=bytearray(b'OPAY'+bytes((target,0,0,0)));pos=8
    head=pay._HEAD;dest=pay._HEAD_V1 if target==1 else pay._HEAD_V3
    while pos<len(blob):
        fields=head.unpack_from(blob,pos);start=pos;pos+=head.size
        labels=fields[19];qtypes=fields[33]
        label_end=pos+labels*pay._LABEL.size
        qtype_end=label_end+qtypes*pay._QTYPE.size
        up,down=struct.unpack_from('<HH',blob,qtype_end)
        end=qtype_end+4+up+down
        if end>len(blob):raise ValueError('truncated payload tail')
        out.extend(blob[start:start+dest.size]);out.extend(blob[pos:label_end])
        if target==3:out.extend(blob[label_end:qtype_end])
        out.extend(blob[qtype_end:end]);pos=end
    tmp=path.with_suffix('.pay.partial');tmp.write_bytes(out)
    list(pay.read_sidecar(tmp));tmp.replace(path)
