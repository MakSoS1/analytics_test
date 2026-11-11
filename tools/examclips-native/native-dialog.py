#!/usr/bin/env python3
"""Operate a real Chrome Linux save dialog using focused X11 input.

No browser API, file handle or writable stream is replaced. Desktop captures
belong to private encrypted technical evidence, never public report visuals.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

def now(): return datetime.now(timezone.utc).isoformat()

def command(args,timeout=10,check=True):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    if check and result.returncode: raise ValueError('X11_COMMAND_FAILED')
    return result

def window_id(value):
    value=str(value).strip()
    return str(int(value,16) if value.lower().startswith('0x') else int(value))

def snapshot():
    result=command(['xdotool','search','--onlyvisible','--name','.'],check=False)
    active=command(['xdotool','getactivewindow'],check=False).stdout.strip()
    rows=[]
    for raw in result.stdout.splitlines():
        if not raw.isdigit(): continue
        props=command(['xprop','-id',raw,'WM_CLASS','WM_TRANSIENT_FOR','_NET_WM_WINDOW_TYPE','_NET_WM_PID'],check=False).stdout
        name=command(['xdotool','getwindowname',raw],check=False).stdout.strip()
        match=re.search(r'WM_TRANSIENT_FOR.*?window id #\s*(0x[0-9a-fA-F]+|[0-9]+)',props)
        classes=re.search(r'WM_CLASS[^=]*=\s*(.*)',props)
        pid=re.search(r'_NET_WM_PID[^=]*=\s*(\d+)',props)
        rows.append({'id':raw,'name':name[:600],'class':classes.group(1) if classes else '',
                     'dialog':'_NET_WM_WINDOW_TYPE_DIALOG' in props,
                     'transient_for':window_id(match.group(1)) if match else None,
                     'pid':int(pid.group(1)) if pid else None,'active':raw==active})
    return rows

def choose_dialog(before,after):
    known={str(w['id']) for w in before}
    chrome={str(w['id']) for w in before if re.search(r'chrome|chromium',w.get('class',''),re.I)}
    matches=[w for w in after if str(w['id']) not in known
             and re.search(r'chrome|chromium',w.get('class',''),re.I)
             and re.search(r'save|сохран',w.get('name',''),re.I)
             and (w.get('dialog') or str(w.get('transient_for')) in chrome)]
    if len(matches)>1: raise ValueError('AMBIGUOUS_SAVE_DIALOG')
    return matches[0] if matches else None

def validate_destination(destination,case_directory):
    target=Path(destination).absolute();root=Path(case_directory).resolve(strict=True)
    if target.parent.resolve(strict=True)!=root or target.name!='native-clip.mp4':
        raise ValueError('DESTINATION_OUTSIDE_CASE_DIRECTORY')
    if target.exists() or target.is_symlink(): raise ValueError('DESTINATION_EXISTS')
    return root/target.name

def capture(path):
    size=os.environ.get('NATIVE_DESKTOP_SIZE','1920x1080')
    if not re.fullmatch(r'\d{3,4}x\d{3,4}',size): raise ValueError('INVALID_DESKTOP_SIZE')
    command(['ffmpeg','-nostdin','-v','error','-f','x11grab','-video_size',size,'-i',os.environ['DISPLAY'],
             '-frames:v','1','-threads','1','-y',str(path)],timeout=20)

def operate(before,destination,case_directory,evidence_directory,timeout_seconds=60):
    target=validate_destination(destination,case_directory)
    evidence=Path(evidence_directory);evidence.mkdir(mode=0o700,parents=True,exist_ok=True)
    deadline=time.monotonic()+timeout_seconds;dialog=None
    record={'started_utc':now(),'method':'Real focused X11 keyboard input into observed Chrome save dialog',
            'native_api_replaced':False,'before_windows':before,'status':'waiting_for_native_save_dialog'}
    report=evidence/'native-dialog.json'
    def save():report.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
    save()
    try:
        while time.monotonic()<deadline:
            observed=snapshot();dialog=choose_dialog(before,observed)
            if dialog:break
            time.sleep(.4)
        if not dialog:raise ValueError('NATIVE_SAVE_DIALOG_NOT_OBSERVED')
        record.update(dialog=dialog,observed_utc=now());save()
        capture(evidence/'01-native-save-dialog.png')
        command(['xdotool','windowactivate','--sync',dialog['id']],timeout=8)
        if command(['xdotool','getactivewindow']).stdout.strip()!=dialog['id']:
            raise ValueError('NATIVE_SAVE_DIALOG_NOT_FOCUSED')
        # XTest input goes to the active real window, not a synthetic browser API.
        command(['xdotool','key','--clearmodifiers','ctrl+l'])
        command(['xdotool','type','--clearmodifiers','--delay','1',str(target)])
        capture(evidence/'02-native-save-path.png')
        command(['xdotool','key','--clearmodifiers','Return'])
        confirm_after=time.monotonic()+2;confirmed=False
        while time.monotonic()<deadline:
            current=snapshot()
            if not any(w['id']==dialog['id'] for w in current):
                record.update(status='native_save_dialog_closed',closed_utc=now(),after_windows=current,
                              destination_name=target.name,destination_exists_at_close=target.exists())
                capture(evidence/'03-after-native-save-dialog.png');save();return record
            if not confirmed and time.monotonic()>=confirm_after:
                if command(['xdotool','getactivewindow']).stdout.strip()!=dialog['id']:
                    raise ValueError('SAVE_DIALOG_LOST_FOCUS')
                # GTK's location entry can first resolve the path; activate its
                # ordinary Save mnemonic only while this exact dialog remains.
                command(['xdotool','key','--clearmodifiers','alt+s']);confirmed=True
            time.sleep(.3)
        raise ValueError('NATIVE_SAVE_DIALOG_DID_NOT_CLOSE')
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) else type(error).__name__
        record.update(status='failed',failure_code=code,finished_utc=now());save()
        try:capture(evidence/'04-native-dialog-failure.png')
        except Exception:pass
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    snap=sub.add_parser('snapshot');snap.add_argument('--output',type=Path,required=True)
    act=sub.add_parser('operate');act.add_argument('--before',type=Path,required=True);act.add_argument('--target',type=Path,required=True)
    act.add_argument('--case-dir',type=Path,required=True);act.add_argument('--evidence-dir',type=Path,required=True);act.add_argument('--timeout',type=float,default=60)
    args=parser.parse_args()
    try:
        if not os.environ.get('DISPLAY'):raise ValueError('X11_DISPLAY_REQUIRED')
        if any(not shutil.which(tool) for tool in ['xdotool','xprop','ffmpeg']):raise ValueError('NATIVE_UI_TOOLS_MISSING')
        if args.mode=='snapshot':args.output.write_text(json.dumps(snapshot(),ensure_ascii=False,indent=2)+'\n')
        else:
            result=operate(json.loads(args.before.read_text()),args.target,args.case_dir,args.evidence_dir,args.timeout)
            print(json.dumps({'status':result['status'],'native_api_replaced':False}))
        return 0
    except Exception as error:
        code=str(error) if isinstance(error,ValueError) and re.fullmatch(r'[A-Z0-9_]+',str(error)) else type(error).__name__
        print(json.dumps({'status':'native_dialog_failed','code':code}),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
