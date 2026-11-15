"""Mirror complete ordinary unencrypted TIB VOD before offline FFmpeg remuxing.

Only standard HTTPS GETs on the source origin are used. No source trimming,
transcoding, decryption, authentication, or alternate access path is provided.
"""
import hashlib
import json
import math
import pathlib
import re
import urllib.parse
import urllib.request

def _tib_url(url):
    p=urllib.parse.urlsplit(url)
    if p.scheme!='https' or p.hostname!='av.tib.eu' or p.port not in (None,443) or p.username or p.password:
        raise ValueError('Public TIB request must stay on the original HTTPS origin')
    return url

class TibRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        _tib_url(newurl)
        return super().redirect_request(request,fp,code,message,headers,newurl)


def public_tib_fetch(url):
    _tib_url(url)
    opener=urllib.request.build_opener(TibRedirectHandler())
    return opener.open(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=60)



def mirror_vod_hls(url, destination, fetch=None, max_bytes=2_000_000_000):
    fetch=public_tib_fetch if fetch is None else fetch
    destination=pathlib.Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    origin=urllib.parse.urlsplit(url)
    if origin.scheme!='https' or origin.hostname!='av.tib.eu' or origin.port not in (None,443) or origin.username or origin.password:
        raise ValueError('Only the ordinary public TIB HTTPS origin is supported')
    fetched={}; records=[]; total=0

    def checked(candidate):
        p=urllib.parse.urlsplit(candidate)
        if p.scheme!='https' or p.hostname!=origin.hostname or p.port not in (None,443) or p.username or p.password:
            raise ValueError('Playlist URI must remain on the original HTTPS origin')
        return candidate

    def response_ok(response):
        checked(response.geturl())
        if response.status!=200:
            raise ValueError('Public source GET did not return a complete HTTP200 response')

    def playlist(candidate):
        checked(candidate)
        with fetch(candidate) as response:
            response_ok(response)
            effective_url=response.geturl()
            raw=response.read(4_000_001)
        if len(raw)>4_000_000:
            raise ValueError('Public playlist exceeds bounded VOD metadata size')
        text=raw.decode('utf-8-sig')
        if not text.startswith('#EXTM3U'):
            raise ValueError('Source is not an ordinary HLS playlist')
        if '#EXT-X-KEY:' in text or '#EXT-X-SESSION-KEY:' in text:
            raise ValueError('Cannot mirror encrypted media')
        return text.splitlines(),effective_url

    def attributes(line):
        return {key:value[1:-1] if value.startswith('"') else value for key,value in re.findall(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)',line.split(':',1)[1])}

    def store_media(candidate):
        nonlocal total
        checked(candidate)
        if candidate in fetched:return fetched[candidate]
        suffix=pathlib.PurePosixPath(urllib.parse.urlsplit(candidate).path).suffix
        if suffix not in ('.mp4','.m4s','.ts','.aac'):suffix='.bin'
        name=hashlib.sha256(candidate.encode()).hexdigest()[:20]+suffix
        target=destination/name; partial=destination/(name+'.part'); digest=hashlib.sha256(); size=0
        try:
            with fetch(candidate) as response:
                response_ok(response)
                advertised=response.headers.get('Content-Length')
                advertised=int(advertised) if advertised is not None else None
                if advertised is not None and (advertised<=0 or total+advertised>max_bytes):
                    raise ValueError('Complete media exceeds the source byte budget')
                with partial.open('wb') as output:
                    while block:=response.read(1024*1024):
                        size+=len(block)
                        if total+size>max_bytes:raise ValueError('Complete media exceeds the source byte budget')
                        output.write(block);digest.update(block)
                if not size or advertised is not None and size!=advertised:
                    raise ValueError('Public media response ended before its complete declared length')
            partial.replace(target)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        total+=size; fetched[candidate]=name
        records.append({'local_file':name,'bytes':size,'sha256':digest.hexdigest()})
        return name

    def mirror_media(candidate, name, lines=None):
        if lines is None:lines,candidate=playlist(candidate)
        if any(line.split(':',1)[0] in {'#EXT-X-GAP','#EXT-X-SKIP','#EXT-X-I-FRAMES-ONLY'} for line in lines):
            raise ValueError('VOD explicitly declares missing or partial media')
        if '#EXT-X-ENDLIST' not in lines or not any(line.startswith('#EXTINF:') for line in lines):
            raise ValueError('Only complete finite VOD playlists are supported')
        if any(line.startswith('#EXT-X-STREAM-INF:') for line in lines):
            raise ValueError('Nested master playlists are not supported')
        rewritten=[]; pending_duration=None; pending_range=None; previous_media=None; previous_end=None; ended=False

        def check_range(value, local_file, inherited=None):
            match=re.fullmatch(r'(\d+)(?:@(\d+))?',value or '')
            if not match or int(match[1])<=0:
                raise ValueError('Invalid byte range in complete media playlist')
            offset=int(match[2]) if match[2] is not None else inherited
            if offset is None or offset<0 or offset+int(match[1])>(destination/local_file).stat().st_size:
                raise ValueError('Media byte range is incomplete or exceeds the downloaded track')
            return offset+int(match[1])

        for line in lines:
            if line.startswith('#EXTINF:'):
                if ended or pending_duration is not None:
                    raise ValueError('EXTINF is not paired with exactly one complete media segment')
                pending_duration=float(line.split(':',1)[1].split(',',1)[0])
                if not math.isfinite(pending_duration) or pending_duration<=0:
                    raise ValueError('Invalid EXTINF segment duration')
            elif line.startswith('#EXT-X-BYTERANGE:'):
                if ended or pending_duration is None or pending_range is not None:
                    raise ValueError('Byte range is not paired with a single media segment')
                pending_range=line.split(':',1)[1]
            elif line and not line.startswith('#'):
                if ended or pending_duration is None:
                    raise ValueError('Media segment is missing its EXTINF duration')
                remote=urllib.parse.urljoin(candidate,line)
                local=store_media(remote)
                if pending_range is not None:
                    previous_end=check_range(pending_range,local,previous_end if remote==previous_media else None)
                else:previous_end=None
                previous_media=remote;pending_duration=None;pending_range=None;line=local
            elif line.startswith('#EXT-X-MAP:'):
                attrs=attributes(line);match=re.search(r'URI="([^"]+)"',line)
                if not match:raise ValueError('Initialization map is missing its media URI')
                local=store_media(urllib.parse.urljoin(candidate,match.group(1)))
                if 'BYTERANGE' in attrs:check_range(attrs['BYTERANGE'],local)
                line=line[:match.start(1)]+local+line[match.end(1):]
            elif line=='#EXT-X-ENDLIST':
                if pending_duration is not None or pending_range is not None:
                    raise ValueError('Final media segment is incomplete')
                ended=True
            elif 'URI=' in line:
                raise ValueError('Unsupported external URI in media playlist')
            rewritten.append(line)
        if pending_duration is not None or pending_range is not None:
            raise ValueError('Final media segment is incomplete')
        (destination/name).write_text('\n'.join(rewritten)+'\n',encoding='utf-8')
        return name

    lines,url=playlist(url)
    variants=[]
    for i,line in enumerate(lines):
        if line.startswith('#EXT-X-STREAM-INF:'):
            a=attributes(line); resolution=a.get('RESOLUTION','')
            match=re.fullmatch(r'(\d+)x(\d+)',resolution)
            if not match or i+1>=len(lines) or not lines[i+1] or lines[i+1].startswith('#'):
                raise ValueError('Video variant is missing its resolution or media URI')
            variants.append((int(match[1])*int(match[2]),int(a.get('BANDWIDTH',0)),line,lines[i+1],a))
    if variants:
        _,_,selected,video_uri,video_attrs=max(variants,key=lambda row:(row[0],row[1]))
        master=['#EXTM3U','#EXT-X-VERSION:6','#EXT-X-INDEPENDENT-SEGMENTS']
        group=video_attrs.get('AUDIO')
        if group:
            candidates=[line for line in lines if line.startswith('#EXT-X-MEDIA:') and attributes(line).get('TYPE')=='AUDIO' and attributes(line).get('GROUP-ID')==group]
            if not candidates:raise ValueError('Selected video has no matching complete audio rendition')
            audio=next((line for line in candidates if attributes(line).get('DEFAULT')=='YES'),candidates[0]); attrs=attributes(audio)
            if not attrs.get('URI'):raise ValueError('Separate audio rendition has no public media URI')
            mirror_media(urllib.parse.urljoin(url,attrs['URI']),'audio.m3u8')
            master.append(re.sub(r'URI="[^"]+"','URI="audio.m3u8"',audio))
        mirror_media(urllib.parse.urljoin(url,video_uri),'video.m3u8')
        master.extend([selected,'video.m3u8'])
        (destination/'master.m3u8').write_text('\n'.join(master)+'\n',encoding='utf-8')
        result=destination/'master.m3u8'
    else:
        mirror_media(url,'media.m3u8',lines)
        result=destination/'media.m3u8'
    (destination/'transport-receipt.json').write_text(json.dumps({'method':'complete unencrypted public VOD mirrored over ordinary HTTPS and remuxed offline','source_host':origin.hostname,'source_playlist_sha256':hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),'full_media_bytes':total,'assets':records,'selected_variant':selected if variants else None},indent=2)+'\n')
    return result
