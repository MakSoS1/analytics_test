#!/usr/bin/env python3
"""Synthetic, public-safe OCR benchmark. No user video/frames are checked into GitHub."""
import json, re, time, sys, os, platform, traceback
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import pytesseract

OUT=Path("ocr_benchmark_results"); OUT.mkdir(exist_ok=True)
FONT="/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BOLD="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
cases=[
 {"id":"lecture_ui_en","lang":"en","reference":["Explore how each method works","Detailed guide","Overview","EPDE","PySINDy"]},
 {"id":"technical_board_en","lang":"en","reference":["Docker Architecture & Image Model","Container runtime","Layers","Dockerfile","Volumes"]},
 {"id":"lecture_board_ru","lang":"cyrillic","reference":["Как работают контейнеры","Изоляция процессов","Виртуальная машина","Сеть контейнеров"]},
]
def norm(s): return re.sub(r"[^a-zа-яё0-9]","",s.casefold())
def draw_case(case):
    im=Image.new("RGB",(1440,810),"#FAFBFD");d=ImageDraw.Draw(im)
    n=case["id"]
    if n=="lecture_ui_en":
        d.text((80,50),case["reference"][0],font=ImageFont.truetype(BOLD,57),fill="#17324C")
        d.text((80,190),case["reference"][1],font=ImageFont.truetype(FONT,40),fill="#243653")
        names=case["reference"][2:]
        for j,name in enumerate(names):
            x=80+j*290
            d.rounded_rectangle((x,260,x+280,340),radius=12,fill=("#DCE9FC" if j==0 else "#FAFBFD"),outline=("#1876EF" if j==0 else "#CDD4DB"),width=3)
            d.text((x+28,276),name,font=ImageFont.truetype(FONT,38),fill=("#166DEA" if j==0 else "#142B48"))
    elif n=="technical_board_en":
        d.text((60,65),case["reference"][0],font=ImageFont.truetype(BOLD,49),fill="#19191F")
        for k,text in enumerate(case["reference"][1:]):
            x=90+(k%2)*675;y=270+(k//2)*205
            d.rounded_rectangle((x,y,x+495,y+140),radius=14,fill="#E7F4FC",outline="#4CA7D9",width=5)
            d.text((x+22,y+39),text,font=ImageFont.truetype(FONT,36),fill="#263B4F")
    else:
        d.text((60,65),case["reference"][0],font=ImageFont.truetype(BOLD,51),fill="#20262F")
        for k,text in enumerate(case["reference"][1:]):
            d.text((110,255+k*145),text,font=ImageFont.truetype(FONT,43),fill="#303C50")
    target=OUT/(n+".png");im.save(target)
    return target

def scored(name,case,text,time_seconds):
    return {"model":name,"case":case["id"],"lang":case["lang"],"seconds":round(time_seconds,4),
       "expected":case["reference"],"matched":[s for s in case["reference"] if norm(s) in norm(text)],
       "target_recall":round(sum(norm(s) in norm(text) for s in case["reference"])/len(case["reference"]),3),
       "output":text[:1500]}

results=[];errors=[]
for case in cases:
    path=draw_case(case)
    for psm in [6,11]:
        t0=time.perf_counter()
        try:
            text=pytesseract.image_to_string(str(path),lang="rus+eng" if case["lang"]=="cyrillic" else "eng",config=f"--psm {psm}")
            results.append(scored("Tesseract PSM"+str(psm),case,text,time.perf_counter()-t0))
        except Exception as exc:errors.append(f"Tesseract {case['id']}:{str(exc)[:200]}")
try:
    from rapidocr import RapidOCR, LangDet, LangRec, OCRVersion, ModelType
    configs=[
      ("PP-OCRv6 small EN",{
        "Det.ocr_version":OCRVersion.PPOCRV6,"Det.model_type":ModelType.SMALL,"Det.lang_type":LangDet.EN,
        "Rec.ocr_version":OCRVersion.PPOCRV6,"Rec.model_type":ModelType.SMALL,"Rec.lang_type":LangRec.EN,
        "Global.text_score":0.35
      },"en"),
      ("PP-OCRv5 Cyrillic mobile",{
        "Det.ocr_version":OCRVersion.PPOCRV5,"Det.model_type":ModelType.MOBILE,"Det.lang_type":LangDet.CH,
        "Rec.ocr_version":OCRVersion.PPOCRV5,"Rec.model_type":ModelType.MOBILE,"Rec.lang_type":LangRec.CYRILLIC,
        "Global.text_score":0.35
      },"cyrillic")
    ]
    for name,params,lang in configs:
        try:
            ts=time.perf_counter();engine=RapidOCR(params=params)
            first=True
            for case in (c for c in cases if c["lang"]==lang):
                path=OUT/(case["id"]+".png")
                start=time.perf_counter()
                r=engine(str(path))
                elapsed=time.perf_counter()-start
                txts=getattr(r,"txts",None)
                output=" ".join(txts) if txts else ""
                item=scored(name,case,output,elapsed)
                item["first_inference"]=first; item["engine_init_seconds"]=round(start-ts,2) if first else 0
                results.append(item);first=False
        except Exception as exc:
            errors.append(name+": "+str(exc)[:700])
except Exception as exc:errors.append("RapidOCR import: "+str(exc)[:700])
report={"platform":platform.platform(),"python":sys.version.split()[0],"cases":len(cases),
        "comparisons":results,"errors":errors,
        "note":"Synthetic slide reference phrase inclusion; NOT a representative real-lecture character error rate."}
(OUT/"benchmark.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
for row in results: print("BENCH",row["model"],row["case"],"recall",row["target_recall"],"time",row["seconds"],row["output"][:100])
for error in errors:print("OCR_ERROR",error)
print("BENCHMARK_REPORT",str(OUT/"benchmark.json"))
# If no Paddle result exists the benchmark is incomplete; fail visibly rather than claiming successful comparison.
if not any(x["model"].startswith("PP-") for x in results):raise SystemExit(4)
