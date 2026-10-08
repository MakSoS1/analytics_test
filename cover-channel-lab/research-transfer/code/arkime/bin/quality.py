"""Capture accounting is explicit; missing counters never imply zero loss."""
import re

def capture_quality(log,reason,returncode,expected_frames=None):
 counts={}
 for target,label in [('captured','packets captured'),('received','packets received by filter'),('kernel_dropped','packets dropped by kernel')]:
  matches=re.findall(r'(?m)^([0-9]+) '+re.escape(label)+r'\s*$',log)
  counts[target]=int(matches[-1]) if matches else None
 counts.update(reason=reason.strip(),capture_returncode=int(returncode))
 counts['loss_free']=counts['kernel_dropped']==0 and all(counts[k] is not None for k in ('captured','received'))
 counts['duration_completed']=counts['reason']=='duration' and counts['capture_returncode'] in (0,124)
 counts['frames_reconciled']=None if expected_frames is None else counts['captured']==expected_frames
 return counts
