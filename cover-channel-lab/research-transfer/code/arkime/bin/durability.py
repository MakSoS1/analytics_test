import os
from pathlib import Path
from pipeline import fsync_dir

def durable_directory(root):
 root=Path(root)
 for p in root.rglob('*'):
  if p.is_file():
   with p.open('rb') as f:os.fsync(f.fileno())
 for p in sorted((p for p in root.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):fsync_dir(p)
 fsync_dir(root);fsync_dir(root.parent)

def load_baseline(office):
 # Add barrier BEFORE original code removes previous checkpoints.
 # Compile original code in memory, preserve path/numerical behavior.
 import types
 path=Path(office)/'office_batches.py';source=path.read_text()
 anchor='        # ---- what this batch no longer needs --------------------------------'
 if source.count(anchor)!=1:raise RuntimeError('baseline durability integration anchor changed')
 source=source.replace(anchor,'        from durability import durable_directory\n        durable_directory(out)\n'+anchor)
 module=types.ModuleType('office_batches_durable');module.__file__=str(path)
 exec(compile(source,str(path),'exec'),module.__dict__)
 return module
