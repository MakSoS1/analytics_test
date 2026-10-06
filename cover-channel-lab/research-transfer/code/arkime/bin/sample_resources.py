import json,time,subprocess,argparse
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('unit');p.add_argument('out',type=Path);p.add_argument('--seconds',type=int,default=180);a=p.parse_args()
with a.out.open('w') as f:
 for _ in range(a.seconds//2):
  raw=subprocess.check_output(['systemctl','--user','show',a.unit,'-p','MemoryCurrent','-p','MemoryPeak','-p','ActiveState'],text=True)
  row=dict(x.split('=',1) for x in raw.strip().splitlines());row['time']=time.time();row['free_disk']=__import__('shutil').disk_usage(a.out.parent).free
  f.write(json.dumps(row)+'\n');f.flush()
  if row['ActiveState'] not in ('active','activating'):break
  time.sleep(2)
