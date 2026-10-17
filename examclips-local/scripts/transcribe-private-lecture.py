#!/usr/bin/env python3
"""Local-only ASR for private lecture audit. Never uploads video/audio."""
import argparse, json, os, pathlib, sys, time

def to_srt_time(v):
    ms=max(0,round(float(v)*1000))
    h,ms=divmod(ms,3600000);m,ms=divmod(ms,60000);s,ms=divmod(ms,1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--video",required=True)
    p.add_argument("--out",required=True)
    p.add_argument("--model",default="small")
    p.add_argument("--language",default="en")
    a=p.parse_args()
    inp=pathlib.Path(a.video)
    if not inp.exists(): raise SystemExit("Source lecture file not found")
    out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=True)
    import faster_whisper
    start=time.monotonic()
    modes=[("cuda","float16"),("cuda","int8_float16"),("cpu","int8")]
    errors=[]
    model=None
    for device,precision in modes:
        try:
            model=faster_whisper.WhisperModel(a.model,device=device,compute_type=precision,cpu_threads=min(8,os.cpu_count() or 4))
            used={"device":device,"precision":precision,"model":a.model}
            break
        except Exception as e:
            errors.append(f"{device}/{precision}: {str(e)[:180]}")
    if model is None: raise RuntimeError("; ".join(errors))
    print("ASR_DEVICE",json.dumps(used),flush=True)
    segments,info=model.transcribe(str(inp),language=a.language,beam_size=5,
        vad_filter=True,vad_parameters={"min_silence_duration_ms":600},
        word_timestamps=False,condition_on_previous_text=False,
        compression_ratio_threshold=2.4,no_speech_threshold=0.55)
    rows=[]
    for segment in segments:
        text=segment.text.strip()
        if text and segment.end>segment.start:
            rows.append({"start":round(segment.start,3),"end":round(segment.end,3),"text":text,
                         "no_speech_prob":round(segment.no_speech_prob,4)})
        if len(rows)%100==0 and rows:
            print("ASR_PROGRESS",len(rows),f"last_second={rows[-1]['end']:.0f}",flush=True)
    transcript=out/"lecture-transcript.json"
    transcript.write_text(json.dumps({"model":used,"language":a.language,"rows":rows},ensure_ascii=False,indent=2),encoding="utf-8")
    with (out/"lecture.srt").open("w",encoding="utf-8") as f:
        for i,row in enumerate(rows,1):
            f.write(f"{i}\n{to_srt_time(row['start'])} --> {to_srt_time(row['end'])}\n{row['text']}\n\n")
    report={"segments":len(rows),"duration_from_asr":rows[-1]["end"] if rows else 0,
        "elapsed_s":round(time.monotonic()-start,1),"device":used,"errors":errors}
    (out/"asr-metadata.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print("ASR_COMPLETE",json.dumps(report),flush=True)
if __name__=="__main__":main()
