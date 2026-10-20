/** Join ASR line wraps for planning only; original transcript/evidence stays intact.
 * A long silence or 45-second span stops joining uncertain punctuation-free ASR.
 */
export function joinSpeechSentences(rows){
 const result=[];
 for(const row of rows){
  const previous=result.at(-1);
  if(previous&&!/[.!?…。！？]["'»”)]?\s*$/u.test(previous.text)&&
     row.start-previous.end<=.8&&row.start>=previous.end-.05&&row.end-previous.start<=45){
   previous.end=row.end;previous.text+=' '+String(row.text||'').trim();
  }else result.push({...row});
 }
 return result;
}
