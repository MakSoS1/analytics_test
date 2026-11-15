// A diagnostic control is evidence only; it cannot substitute for the required gate.
export async function runRequiredGate({runPrimary,runControl,remaining}){
 const primary=await runPrimary();
 let control={status:'not_run',reason:'primary_passed'};
 if(primary.status!=='passed'){
  if(!primary.asrStarted)control={status:'not_run',reason:'asr_not_started'};
  else if(primary.browserClosed!==true)control={status:'not_run',reason:'primary_browser_not_closed'};
  else if(remaining()<210000)control={status:'not_run',reason:'insufficient_time'};
  else{
   try{control=await runControl(180000)}
   catch(error){control={status:'failed',errorType:String(error?.name||'Error').slice(0,80),reason:'control_exception'}}
  }
 }
 return {primary,control,releaseMatrix:primary.status==='passed'};
}
