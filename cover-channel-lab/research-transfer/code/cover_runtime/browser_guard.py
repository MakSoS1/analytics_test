"""End an owned browser process group before its profile context exits."""
import os
from pathlib import Path
import signal
import subprocess
import time

ORIGINAL_RUN=subprocess.run


def browser_run(command, **kwargs):
    if not isinstance(command,(list,tuple)) or not any(s in Path(str(command[0])).name for s in ('chromium','google-chrome')):
        return ORIGINAL_RUN(command,**kwargs)
    kwargs=dict(kwargs);timeout=kwargs.pop('timeout',None);check=kwargs.pop('check',False)
    if kwargs.pop('capture_output',False):kwargs.update(stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    data=kwargs.pop('input',None);kwargs.pop('start_new_session',None)
    if data is not None:kwargs['stdin']=subprocess.PIPE
    process=subprocess.Popen(command,start_new_session=True,**kwargs)
    try:
        stdout,stderr=process.communicate(data,timeout=timeout)
    finally:
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        time.sleep(.05)
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        process.wait()
    result=subprocess.CompletedProcess(command,process.returncode,stdout,stderr)
    if check:result.check_returncode()
    return result


def install():subprocess.run=browser_run
