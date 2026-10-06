from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

from . import run_campaign as _rc

_ORIGINAL = _rc.execute_http


def _headers_args(headers: dict) -> list[str]:
    return [f"{k}={v}" for k,v in headers.items()]


def execute_http_v3(client_impl: str, method: str, url: str, headers: dict, body: bytes|None, use_h2: bool):
    payload=base64.b64encode(body or b'').decode()
    if client_impl == 'java_httpclient':
        cp=subprocess.run(['java','-cp',os.environ.get('COVERLAB_JAVA_CLIENT_DIR','/tmp/coverlab-java-client'),'CoverlabJavaClient',url,method,payload,*_headers_args(headers)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
        if cp.returncode != 0: raise RuntimeError('java_httpclient failed: '+cp.stderr[-500:])
        return int(cp.stdout.strip().splitlines()[-1]), 'java_httpclient'
    if client_impl == 'rust_reqwest':
        exe=os.environ.get('COVERLAB_RUST_CLIENT','/tmp/coverlab-rust-client')
        cp=subprocess.run([exe,url,method,payload,*_headers_args(headers)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
        if cp.returncode != 0: raise RuntimeError('rust_reqwest failed: '+cp.stderr[-500:])
        return int(cp.stdout.strip().splitlines()[-1]), 'rust_reqwest'
    return _ORIGINAL(client_impl,method,url,headers,body,use_h2)


def install():
    _rc.execute_http=execute_http_v3
    # orchestrate imported the run() function, which resolves execute_http in
    # run_campaign's module globals, so patching this module is sufficient.

