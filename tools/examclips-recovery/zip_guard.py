import hashlib,json,pathlib,stat,sys,zipfile
def sha(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def checked_members(z,case=None,outer=False):
    infos=z.infolist()
    if not infos or len(infos)>10000:raise ValueError('INVALID_MEMBER_COUNT')
    seen=set();total=0
    for i in infos:
        n=i.filename
        p=pathlib.PurePosixPath(n)
        if not n or '\x00' in n or '\\' in n or p.is_absolute() or '..' in p.parts or '.' in p.parts or n.startswith('/') or '//' in n:raise ValueError('UNSAFE_MEMBER_PATH')
        key=n.rstrip('/').casefold()
        if key in seen:raise ValueError('DUPLICATE_MEMBER')
        seen.add(key)
        if stat.S_ISLNK(i.external_attr>>16):raise ValueError('SYMLINK_MEMBER')
        if i.flag_bits&1:raise ValueError('ENCRYPTED_ZIP_MEMBER')
        if i.is_dir():continue
        if outer and n not in {'encryption.json','parts.json','evidence.enc.part'}:raise ValueError('UNEXPECTED_OUTER_MEMBER')
        if not outer and n!='run.json' and (not case or p.parts[0]!=case):raise ValueError('WRONG_CASE_MEMBER')
        if i.file_size<0 or i.file_size>5*1024**3:raise ValueError('MEMBER_SIZE_LIMIT')
        total+=i.file_size
        if total>6*1024**3:raise ValueError('ARCHIVE_SIZE_LIMIT')
    if outer and {i.filename for i in infos if not i.is_dir()}!={'encryption.json','parts.json','evidence.enc.part'}:raise ValueError('MISSING_OUTER_MEMBER')
    return infos
def extract(source,destination,case=None,outer=False):
    destination=pathlib.Path(destination).resolve();destination.mkdir(parents=True,exist_ok=True,mode=0o700)
    inventory=[]
    with zipfile.ZipFile(source) as z:
        infos=checked_members(z,case,outer)
        for i in infos:
            if i.is_dir():continue
            out=destination.joinpath(*pathlib.PurePosixPath(i.filename).parts)
            if not out.resolve().is_relative_to(destination):raise ValueError('DESTINATION_ESCAPE')
            out.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if out.exists():raise ValueError('EXTRACTION_OVERWRITE')
            with z.open(i) as incoming,out.open('xb') as target:
                while block:=incoming.read(1024**2):target.write(block)
            out.chmod(0o600)
            if out.stat().st_size!=i.file_size:raise ValueError('EXTRACTED_SIZE_MISMATCH')
            inventory.append({'path':i.filename,'bytes':i.file_size,'sha256':sha(out)})
    return inventory
if __name__=='__main__':
    mode,source,destination=sys.argv[1:4]
    result=extract(source,destination,None if mode=='outer' else sys.argv[4],mode=='outer')
    print(json.dumps(result))
