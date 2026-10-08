"""Explicit logical endpoint mapping with consistent packet/payload directions."""
import hashlib
import ipaddress
import json
import struct
from pathlib import Path
from .records import RECORD, iter_rows, merge_rows
from .source import sha256
from .wire_observation import convert_supported_rows
from .cover_registry import digest


def map_endpoints(observation: dict, mapping: dict, out: Path) -> dict:
    import payload_sidecar as pay
    endpoints=mapping['endpoints'];keys={};private={}
    for address,target in endpoints.items():
        new=bytes.fromhex(target['key'])
        if len(new)!=8 or target['private'] not in (0,1):raise ValueError('invalid endpoint identity/private flag')
        old=hashlib.blake2s(ipaddress.ip_address(address).packed,key=b'cover-isolated-research-v1'.ljust(32,b'\0'),digest_size=8).digest()
        keys[old]=new;private[old]=target['private']
    if len(set(keys.values()))!=len(keys):raise ValueError('endpoint mapping collision')
    out=Path(out);converted=convert_supported_rows(observation,out/'source')
    delta=float(mapping.get('event_time_offset',0));target=out/'mapped.pkts'
    with target.open('wb') as f:
        for fields,_ in iter_rows(converted['pkts_path']):
            x=list(fields);a,b=x[1:3]
            if a not in keys or b not in keys:raise ValueError('endpoint absent from mapping')
            x[0]+=delta;x[1]=keys[a];x[2]=keys[b];x[9]=(x[9]&~3)|private[a]|(private[b]<<1)
            f.write(RECORD.pack(*x))
    original=Path(converted['pay_path']);list(pay.read_sidecar(original))
    blob=original.read_bytes();pos=8;result=bytearray(blob[:8])
    while pos<len(blob):
        fields=list(pay._HEAD.unpack_from(blob,pos));pos+=pay._HEAD.size
        labels=fields[19]*pay._LABEL.size;types=fields[33]*pay._QTYPE.size
        name_data=blob[pos:pos+labels+types];pos+=labels+types
        nu,nd=struct.unpack_from('<HH',blob,pos);pos+=4
        up=blob[pos:pos+nu];down=blob[pos+nu:pos+nu+nd];pos+=nu+nd
        a,b=fields[0],fields[2]
        if a not in keys or b not in keys:raise ValueError('payload endpoint absent from mapping')
        fields[0]=keys[a];fields[2]=keys[b];fields[6]+=delta;fields[7]+=delta
        if (fields[0],fields[1])>(fields[2],fields[3]):
            for i,j in ((0,2),(1,3),(8,9),(10,11),(12,13),(36,37),(38,39),(40,41),(42,43)):
                fields[i],fields[j]=fields[j],fields[i]
            up,down=down,up
        result.extend(pay._HEAD.pack(*fields));result.extend(name_data)
        result.extend(struct.pack('<HH',len(up),len(down)));result.extend(up);result.extend(down)
    payload=out/'mapped.pay';payload.write_bytes(result);list(pay.read_sidecar(payload))
    manifest={**converted,'pkts_path':str(target),'pay_path':str(payload),'pkts_sha256':sha256(target),'pay_sha256':sha256(payload),
              'mapping_sha256':digest(mapping),'observation_sha256':observation['sha256'],'mapping':mapping}
    (out/'mapping.json').write_text(json.dumps(manifest,indent=2)+'\n');return manifest


def compose_alternative_branches(office_paths, campaigns, out):
    campaigns=list(campaigns)
    if any(c.get('arm') not in ('scenario','control') for c in campaigns):raise ValueError('alternative arms required')
    office_paths=list(map(Path,office_paths));identity=[{'path':str(p),'sha256':sha256(p)} for p in office_paths]
    out=Path(out);out.mkdir(parents=True,exist_ok=True);results={}
    for arm in ('clean','scenario','control'):
        selected=[c for c in campaigns if c['arm']==arm]
        path=out/(arm+'.pkts');stats,gt=merge_rows(office_paths,selected,path)
        results[arm]={'path':str(path),'sha256':sha256(path),'office_sha256':digest(identity),'stats':stats,'memberships':gt}
    (out/'branches.json').write_text(json.dumps(results,indent=2)+'\n');return results
