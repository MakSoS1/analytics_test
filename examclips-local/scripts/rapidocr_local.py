#!/usr/bin/env python3
"""Opt-in on-device PP-OCR inference for ExamClips. Reads one PNG from STDIN.
Only local video frames are accepted. Never opens network requests to upload frames.
RapidOCR may download PUBLIC model weights at first use.
"""
import base64, io, json, sys, time
from PIL import Image, ImageOps

def output(body):
    sys.stdout.write(json.dumps(body,ensure_ascii=False,separators=(",",":"))+"\n")
    sys.stdout.flush()

def check():
    from importlib.metadata import version
    output({"ok":True,"version":version("rapidocr"),"models":["PP-OCRv6 small EN","PP-OCRv5 Cyrillic mobile"]})

def convert(data):
    if not isinstance(data,dict): raise ValueError("Not a JSON object")
    language=data.get("language","en")
    if language not in ("en","ru"): raise ValueError("Only en or ru is supported")
    raw=base64.b64decode(data.get("png_base64",""),validate=True)
    if len(raw)>3_500_000 or len(raw)<80 or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Must supply a PNG smaller than 3.5 MB")
    im=Image.open(io.BytesIO(raw))
    if im.format!="PNG" or im.width>2500 or im.height>1800 or im.width*im.height>4_000_000:
        raise ValueError("Unsupported image dimensions")
    im=ImageOps.exif_transpose(im).convert("RGB")
    return language,im

def perform(payload):
    lang,im=convert(payload)
    from rapidocr import RapidOCR, OCRVersion, ModelType, LangDet, LangRec
    from numpy import asarray
    if lang=="ru":
        options={
          "Det.ocr_version":OCRVersion.PPOCRV5,"Det.model_type":ModelType.MOBILE,"Det.lang_type":LangDet.CH,
          "Rec.ocr_version":OCRVersion.PPOCRV5,"Rec.model_type":ModelType.MOBILE,"Rec.lang_type":LangRec.CYRILLIC,
          "Global.text_score":0.38,
        }
        model="PP-OCRv5 Cyrillic mobile"
    else:
        options={
          "Det.ocr_version":OCRVersion.PPOCRV6,"Det.model_type":ModelType.SMALL,"Det.lang_type":LangDet.EN,
          "Rec.ocr_version":OCRVersion.PPOCRV6,"Rec.model_type":ModelType.SMALL,"Rec.lang_type":LangRec.EN,
          "Global.text_score":0.38,
        }
        model="PP-OCRv6 small EN"
    started=time.perf_counter()
    worker=RapidOCR(params=options)
    result=worker(asarray(im))
    lines=[]
    if result and result.txts is not None and result.boxes is not None:
        for poly,text,score in zip(result.boxes,result.txts,result.scores):
            coords=[(float(p[0]),float(p[1])) for p in poly]
            x0=min(p[0] for p in coords);x1=max(p[0] for p in coords)
            y0=min(p[1] for p in coords);y1=max(p[1] for p in coords)
            if x1<=x0 or y1<=y0 or not text.strip():continue
            lines.append({"text":str(text)[:300],"confidence":round(float(score)*100,2),
             "box":{"x0":round(x0,1),"y0":round(y0,1),"x1":round(x1,1),"y1":round(y1,1)}})
    return {"engine":model,"lines":lines,"elapsed_ms":round((time.perf_counter()-started)*1000)}

if __name__=="__main__":
    try:
        if sys.argv[1:] == ["--probe"]:
            check()
        else:
            raw=sys.stdin.buffer.read(5_000_000)
            if len(raw)>4_800_000: raise ValueError("Request too large")
            output(perform(json.loads(raw.decode("utf8"))))
    except Exception as exc:
        sys.stderr.write("EXAMCLIPS_LOCAL_OCR_ERROR "+str(exc)[:180]+"\n")
        sys.exit(2)
