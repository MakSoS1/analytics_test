from __future__ import annotations

import argparse
import json
import math
import shutil
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, precision_score, recall_score, roc_auc_score
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from . import train_baseline as _base
from . import train_baseline_v2 as _v2
from .research_contract_v3 import validation_role
from .train_baseline_v3 import availability_flags_v3

MAX_SEQ_LEN = 96
OPAQUE_CHANNELS = (
    'direction','size','delta_t','transport_tcp','transport_udp',
    'tcp_syn','tcp_ack','tcp_fin','tcp_rst','tcp_psh','tcp_retransmit','flow_boundary',
)
PROTOCOL_BUCKETS=('http','https','h2','h3','wss','grpc','mqtt','quic','other')
KIND_BUCKETS=('poll','request','response','result','upload','download','heartbeat','other')
VISIBLE_CHANNELS=('direction','size','delta_t','status') + tuple(f'protocol_{x}' for x in PROTOCOL_BUCKETS) + tuple(f'kind_{x}' for x in KIND_BUCKETS)
SEQ_CHANNELS=OPAQUE_CHANNELS


def _numeric(series: pd.Series | None, n: int) -> np.ndarray:
    if series is None:return np.zeros(n,dtype=np.float32)
    return pd.to_numeric(series,errors='coerce').fillna(0).to_numpy(dtype=np.float32)


def _truncate(g: pd.DataFrame,max_len:int) -> pd.DataFrame:
    g=g.sort_values('ts') if 'ts' in g else g.copy()
    if len(g)<=max_len:return g
    head=max_len//2
    return pd.concat([g.iloc[:head],g.iloc[-(max_len-head):]],ignore_index=True)


def _bucket(value: object,buckets: tuple[str,...]) -> str:
    s=str(value or '').lower()
    for b in buckets[:-1]:
        if b in s:return b
    return buckets[-1]


def encode_opaque_sequence(group: pd.DataFrame,max_len:int=MAX_SEQ_LEN) -> tuple[np.ndarray,np.ndarray]:
    """Packet/transport-only input; no decrypted transaction or HTTP fields."""
    g=_truncate(group,max_len);n=len(g)
    out=np.zeros((len(OPAQUE_CHANNELS),max_len),dtype=np.float32);mask=np.zeros(max_len,dtype=np.float32)
    if n==0:return out,mask
    direction=np.clip(_numeric(g.get('direction'),n),-1,1)
    size=np.log1p(np.maximum(_numeric(g.get('packet_size'),n),0))/np.float32(math.log1p(65535))
    if 'delta_t' in g:dt=np.maximum(_numeric(g.get('delta_t'),n),0)
    elif 'ts' in g:
        ts=pd.to_numeric(g['ts'],errors='coerce').ffill().fillna(0).to_numpy(dtype=float);dt=np.diff(ts,prepend=ts[0])
    else:dt=np.zeros(n)
    delta=(np.log1p(dt)/math.log1p(3600)).astype(np.float32)
    transport=g.get('transport',pd.Series(['other']*n)).astype(str).str.lower()
    values=[direction,size,delta,(transport=='tcp').astype(np.float32).to_numpy(),(transport=='udp').astype(np.float32).to_numpy()]
    for c in ('tcp_syn','tcp_ack','tcp_fin','tcp_rst','tcp_psh','tcp_retransmit','flow_boundary'):
        values.append(np.clip(_numeric(g.get(c),n),0,1))
    for i,v in enumerate(values):out[i,:n]=np.asarray(v,dtype=np.float32)[:n]
    mask[:n]=1
    return out,mask


def encode_visible_sequence(group: pd.DataFrame,max_len:int=MAX_SEQ_LEN) -> tuple[np.ndarray,np.ndarray]:
    """Application transaction input; allowed only with actual plaintext visibility."""
    g=_truncate(group,max_len);n=len(g)
    out=np.zeros((len(VISIBLE_CHANNELS),max_len),dtype=np.float32);mask=np.zeros(max_len,dtype=np.float32)
    if n==0:return out,mask
    req=_numeric(g.get('request_body_length'),n);resp=_numeric(g.get('response_body_length'),n);total=req+resp
    direction=np.where(req>resp,1.0,np.where(resp>req,-1.0,0.0)).astype(np.float32)
    size=np.log1p(np.maximum(total,0))/np.float32(math.log1p(1_000_000))
    if 'ts' in g:
        ts=pd.to_numeric(g['ts'],errors='coerce').ffill().fillna(0).to_numpy(dtype=float);dt=np.diff(ts,prepend=ts[0])
    else:dt=np.zeros(n)
    delta=(np.log1p(np.maximum(dt,0))/math.log1p(3600)).astype(np.float32)
    status=np.clip(_numeric(g.get('response_status'),n)/599.0,0,1)
    protocols=[_bucket(v,PROTOCOL_BUCKETS) for v in g.get('protocol',pd.Series(['']*n))]
    kinds=[_bucket(v,KIND_BUCKETS) for v in g.get('kind',pd.Series(['']*n))]
    values=[direction,size,delta,status]
    values += [np.asarray([float(x==b) for x in protocols],dtype=np.float32) for b in PROTOCOL_BUCKETS]
    values += [np.asarray([float(x==b) for x in kinds],dtype=np.float32) for b in KIND_BUCKETS]
    for i,v in enumerate(values):out[i,:n]=v[:n]
    mask[:n]=1
    return out,mask


def encode_sequence(group: pd.DataFrame,max_len:int=MAX_SEQ_LEN):
    return encode_opaque_sequence(group,max_len)


class TinyTCN(nn.Module):
    def __init__(self,channels:int=len(OPAQUE_CHANNELS)):
        super().__init__()
        self.net=nn.Sequential(nn.Conv1d(channels,32,3,padding=1),nn.ReLU(),nn.Conv1d(32,32,3,padding=2,dilation=2),nn.ReLU(),nn.Conv1d(32,20,3,padding=4,dilation=4),nn.ReLU())
        self.head=nn.Sequential(nn.Linear(20,20),nn.ReLU(),nn.Dropout(.10),nn.Linear(20,1))
    def forward(self,x:torch.Tensor,mask:torch.Tensor)->torch.Tensor:
        z=self.net(x);m=mask.unsqueeze(1);pooled=(z*m).sum(dim=2)/m.sum(dim=2).clamp_min(1.0)
        return self.head(pooled).squeeze(1)


def _load_sessions(root:Path)->pd.DataFrame:
    session=_base.load_parquets(root,'session_features.parquet');splits=_base.split_map(root)
    if session.empty:return session
    session=session.drop_duplicates('campaign_id',keep='last').merge(splits,on='campaign_id',how='left');session['split']=session['split'].fillna('challenge')
    return availability_flags_v3(session)


def load_sequence_table(root:Path)->tuple[pd.DataFrame,pd.DataFrame]:
    return _base.load_parquets(root,'packet_sequence_features.parquet'),_load_sessions(root)


def _build_arrays(table:pd.DataFrame,session:pd.DataFrame,ids:Iterable[str],encoder,channels:int):
    ids=[str(x) for x in ids];labels=session.set_index(session.campaign_id.astype(str))['label_binary'].to_dict()
    grouped={str(k):v for k,v in table.groupby(table.campaign_id.astype(str))} if not table.empty else {}
    xs=[];ms=[];ys=[];kept=[]
    for cid in ids:
        g=grouped.get(cid)
        if g is None or cid not in labels:continue
        x,m=encoder(g);xs.append(x);ms.append(m);ys.append(int(labels[cid]));kept.append(cid)
    if not xs:return np.zeros((0,channels,MAX_SEQ_LEN),np.float32),np.zeros((0,MAX_SEQ_LEN),np.float32),np.zeros(0,np.int64),[]
    return np.stack(xs),np.stack(ms),np.asarray(ys,np.int64),kept


def build_sequence_arrays(table:pd.DataFrame,session:pd.DataFrame,ids:Iterable[str]):
    return _build_arrays(table,session,ids,encode_opaque_sequence,len(OPAQUE_CHANNELS))


def build_visible_sequence_arrays(table:pd.DataFrame,session:pd.DataFrame,ids:Iterable[str]):
    return _build_arrays(table,session,ids,encode_visible_sequence,len(VISIBLE_CHANNELS))


def _metrics(y:np.ndarray,p:np.ndarray,threshold:float)->dict:
    pred=(p>=threshold).astype(int);tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    out={'rows':int(len(y)),'positives':int(y.sum()),'threshold':float(threshold),'precision':float(precision_score(y,pred,zero_division=0)),'recall':float(recall_score(y,pred,zero_division=0)),'fpr':float(fp/max(1,fp+tn)),'fp_per_million':float(fp/max(1,fp+tn)*1_000_000),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}
    if len(np.unique(y))>1:out['roc_auc']=float(roc_auc_score(y,p));out['pr_auc']=float(average_precision_score(y,p))
    return out


def _train_one(table:pd.DataFrame,session:pd.DataFrame,out_path:Path,name:str,encoder,channels:tuple[str,...],seed:int,epochs:int,eligible_ids:set[str]|None=None):
    split=session.set_index(session.campaign_id.astype(str))['split'].to_dict();ids_for=lambda part:[c for c,s in split.items() if s==part and (eligible_ids is None or c in eligible_ids)]
    train_ids=ids_for('train');val_ids=ids_for('validation');test_ids=ids_for('test');challenge_ids=ids_for('challenge')
    cal_ids=[c for c in val_ids if validation_role(c)=='expert_calibration'];tune_ids=[c for c in val_ids if validation_role(c)=='expert_threshold']
    builder=lambda ids:_build_arrays(table,session,ids,encoder,len(channels));xtr,mtr,ytr,kept_train=builder(train_ids)
    if len(ytr)<10 or len(np.unique(ytr))<2:return {'name':name,'status':'insufficient_train','train':{'rows':int(len(ytr))}}, {}, None
    torch.manual_seed(seed);np.random.seed(seed);model=TinyTCN(len(channels));pos=max(1,int(ytr.sum()));neg=max(1,len(ytr)-pos)
    loss_fn=nn.BCEWithLogitsLoss(pos_weight=torch.tensor(float(neg/pos)));opt=torch.optim.AdamW(model.parameters(),lr=2e-3,weight_decay=1e-3)
    loader=DataLoader(TensorDataset(torch.tensor(xtr),torch.tensor(mtr),torch.tensor(ytr,dtype=torch.float32)),batch_size=min(128,len(ytr)),shuffle=True,generator=torch.Generator().manual_seed(seed))
    model.train()
    for _ in range(max(1,epochs)):
        for xb,mb,yb in loader:opt.zero_grad();loss=loss_fn(model(xb,mb),yb);loss.backward();opt.step()
    def raw(ids):
        x,m,y,kept=builder(ids)
        if len(y)==0:return y,np.zeros(0),kept
        model.eval()
        with torch.no_grad():p=torch.sigmoid(model(torch.tensor(x),torch.tensor(m))).numpy()
        return y,p,kept
    calibrator=None;ycal,pcal,_=raw(cal_ids)
    if len(ycal) and len(np.unique(ycal))>1:calibrator=IsotonicRegression(out_of_bounds='clip').fit(pcal,ycal)
    calibrate=lambda p:calibrator.predict(p) if calibrator is not None and len(p) else p
    yt,pt,_=raw(tune_ids);pt=calibrate(pt);threshold=_base.threshold_for_recall(yt,pt,.95) if len(yt) and len(np.unique(yt))>1 else .5
    all_ids=session.campaign_id.astype(str).tolist();_,pa,kept=raw(all_ids);pa=calibrate(pa);score_map={c:float(v) for c,v in zip(kept,pa)}
    def report(ids):
        y,p,_=raw(ids);p=calibrate(p);return _metrics(y,p,threshold) if len(y) else {'rows':0}
    bundle={'architecture':'tiny_tcn_1d_cnn','name':name,'visibility':'opaque' if 'opaque' in name else 'visible','channels':list(channels),'max_len':MAX_SEQ_LEN,'threshold':float(threshold),'calibrator':calibrator,'state_dict':model.state_dict(),'seed':seed,'training_campaigns':len(kept_train)}
    torch.save(bundle,out_path)
    rep={'name':name,'status':'ok','architecture':'tiny_tcn_1d_cnn','channels':list(channels),'train':{'rows':len(ytr),'positives':int(ytr.sum())},'test':report(test_ids),'challenge':report(challenge_ids),'threshold':float(threshold)}
    return rep,score_map,bundle


def train_sequences(root:Path,out:Path,seed:int=23,epochs:int=10):
    session=_load_sessions(root);packet=_base.load_parquets(root,'packet_sequence_features.parquet');tx=_base.load_parquets(root,'transaction_features.parquet')
    if session.empty:raise RuntimeError('no session features')
    opaque_rep,opaque_scores,_=_train_one(packet,session,out/'B2-opaque-sequence.pt','B2-opaque-sequence',encode_opaque_sequence,OPAQUE_CHANNELS,seed,epochs)
    if opaque_rep.get('status')!='ok':raise RuntimeError(f"opaque sequence unavailable: {opaque_rep}")
    shutil.copy2(out/'B2-opaque-sequence.pt',out/'B2-sequence.pt')
    encrypted=session.get('availability_encrypted',pd.Series([0]*len(session),index=session.index)).fillna(0).astype(int).eq(1);bypass=session.get('availability_inspection_bypassed',pd.Series([0]*len(session),index=session.index)).fillna(0).astype(int).eq(1)
    visible_ids=set(session.loc[~(encrypted|bypass),'campaign_id'].astype(str))
    visible_rep,visible_scores,_=_train_one(tx,session,out/'B2-visible-sequence.pt','B2-visible-sequence',encode_visible_sequence,VISIBLE_CHANNELS,seed+1,epochs,visible_ids)
    return {'opaque_sequence':opaque_rep,'visible_sequence':visible_rep},opaque_scores,visible_scores


def train_sequence(root:Path,out:Path,seed:int=23,epochs:int=10):
    reports,opaque,_=train_sequences(root,out,seed,epochs);return reports['opaque_sequence'],opaque


def _bundle_probability(bundle:dict,frame:pd.DataFrame)->np.ndarray:
    if frame.empty:return np.zeros(0)
    x,_=_v2.numeric_matrix(frame,bundle['features']);raw=bundle['model'].predict_proba(x)[:,1];cal=bundle.get('calibrator')
    return cal.predict(raw) if cal is not None else raw


def expert_probability_table(root:Path,models:Path,opaque_sequence_scores:dict[str,float],visible_sequence_scores:dict[str,float]|None=None)->pd.DataFrame:
    visible_sequence_scores=visible_sequence_scores or {};frames=_v2.build_frames(root);session=_load_sessions(root)
    keep=[c for c in session.columns if c in {'campaign_id','label_binary','split'} or c.startswith('availability_') or c.startswith('missing_reason_')];base=session[keep].copy();base['campaign_id']=base.campaign_id.astype(str)
    for name,col in (('B2-session','p_b2_visible'),('B3-opaque','p_b3')):
        bundle=joblib.load(models/f'{name}.joblib');frame=frames[name].copy();frame['campaign_id']=frame.campaign_id.astype(str);frame[col]=_bundle_probability(bundle,frame);base=base.merge(frame[['campaign_id',col]],on='campaign_id',how='left')
    b1=frames['B1-content'].copy()
    if not b1.empty:
        bundle=joblib.load(models/'B1-content.joblib');b1['p']=_bundle_probability(bundle,b1);b1['campaign_id']=b1.campaign_id.astype(str);base=base.merge(b1.groupby('campaign_id').p.agg([('p_b1_mean','mean'),('p_b1_max','max')]).reset_index(),on='campaign_id',how='left')
    else:base['p_b1_mean']=np.nan;base['p_b1_max']=np.nan
    base['p_b2_opaque_seq']=base.campaign_id.map(opaque_sequence_scores);base['p_b2_visible_seq']=base.campaign_id.map(visible_sequence_scores)
    encrypted=base.get('availability_encrypted',pd.Series([0]*len(base),index=base.index)).fillna(0).astype(int).eq(1);bypass=base.get('availability_inspection_bypassed',pd.Series([0]*len(base),index=base.index)).fillna(0).astype(int).eq(1);visible=~(encrypted|bypass)
    base['content_available']=(visible & base.p_b1_mean.notna()).astype(int);base['b2_visible_available']=(visible & base.p_b2_visible.notna()).astype(int);base['opaque_sequence_available']=base.p_b2_opaque_seq.notna().astype(int)
    base.loc[~visible,['p_b1_mean','p_b1_max','p_b2_visible','p_b2_visible_seq']]=np.nan
    return base


def train_fusion(root:Path,models:Path,out:Path,opaque_scores:dict[str,float],visible_scores:dict[str,float]|None=None,seed:int=23)->dict:
    table=expert_probability_table(root,models,opaque_scores,visible_scores);val=table[table.split.eq('validation')].copy();test=table[table.split.eq('test')].copy();challenge=table[table.split.eq('challenge')].copy();fit=val[val.campaign_id.map(validation_role).eq('fusion_train')].copy();tune=val[val.campaign_id.map(validation_role).eq('fusion_threshold')].copy()
    feature_cols=[c for c in table.columns if c.startswith('p_') or c.startswith('availability_') or c.startswith('missing_reason_') or c in {'content_available','b2_visible_available','opaque_sequence_available'}]
    if fit.empty or len(fit.label_binary.unique())<2:raise RuntimeError('insufficient disjoint validation campaigns for fusion')
    medians={c:float(pd.to_numeric(fit[c],errors='coerce').median()) if pd.to_numeric(fit[c],errors='coerce').notna().any() else 0.0 for c in feature_cols}
    def matrix(df):
        x=df[feature_cols].apply(pd.to_numeric,errors='coerce').copy()
        for c in feature_cols:x[c]=x[c].fillna(medians[c])
        return x
    fusion=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=seed).fit(matrix(fit),fit.label_binary.astype(int));threshold=.5
    if not tune.empty and len(tune.label_binary.unique())>1:p=fusion.predict_proba(matrix(tune))[:,1];threshold=_base.threshold_for_recall(tune.label_binary.astype(int).to_numpy(),p,.95)
    def report(df):
        if df.empty:return {'rows':0}
        p=fusion.predict_proba(matrix(df))[:,1];return _metrics(df.label_binary.astype(int).to_numpy(),p,threshold)
    bundle={'model':fusion,'features':feature_cols,'medians':medians,'threshold':float(threshold),'router_policy':'opaque/encrypted: B3 + packet-only B2-opaque-sequence; visible: B1 + B2-visible + visible-sequence + B3 + opaque-sequence','plaintext_forbidden_when_opaque':True,'policy_revision':4}
    joblib.dump(bundle,out/'fusion-router.joblib')
    return {'name':'fusion-router','status':'ok','test':report(test),'challenge':report(challenge),'features':feature_cols,'threshold':float(threshold),'policy_revision':4}


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dataset-root',required=True);ap.add_argument('--models',required=True);ap.add_argument('--out',required=True);ap.add_argument('--seed',type=int,default=23);ap.add_argument('--epochs',type=int,default=10)
    a=ap.parse_args();root=Path(a.dataset_root);models=Path(a.models);out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    seq_reports,opaque_scores,visible_scores=train_sequences(root,out,a.seed,a.epochs);fusion=train_fusion(root,models,out,opaque_scores,visible_scores,a.seed)
    report={'policy_revision':4,**seq_reports,'sequence':seq_reports['opaque_sequence'],'fusion':fusion,'opaque_plaintext_leakage_guard':True,'categorical_encoding':'one_hot_visible_only'}
    (out/'advanced_v3_report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
