/** Sentence units for planning. Never estimate word times from character counts.
 * Aligned words allow exact sentence cuts; plain SRT rows remain indivisible.
 */
const TERMINAL=/[.!?…。！？]["'»”)]?\s*$/u;
const ABBREVIATION=/\b(?:Dr|Mr|Mrs|Ms|Prof|vs|etc|e\.g|i\.e)\.$/iu;
export const sentenceEnded=text=>TERMINAL.test(text)&&!ABBREVIATION.test(text);
export function joinSpeechSentences(rows){
 const atoms=[];
 for(const row of rows){
  const words=row.words;
  // Require the complete alignment, not a partial word array for a longer row.
  const normal=s=>String(s).replace(/\s+/gu,'').toLowerCase();
  if(words?.length&&normal(words.map(w=>w.text).join(' '))===normal(row.text)){
   let pending=[];
   const flush=()=>{if(pending.length){atoms.push({...row,start:pending[0].start,end:pending.at(-1).end,text:pending.map(w=>w.text).join(' '),words:pending});pending=[]}};
   for(const w of words){pending.push({...w});if(sentenceEnded(w.text))flush()}
   flush();
  }else atoms.push({...row});
 }
 const result=[];
 for(const row of atoms){
  const previous=result.at(-1);
  // The old 45s cap could put "powerful technique" in the next lesson.
  // Preserve an unfinished sentence even across a long ASR line wrap.
  if(previous&&!sentenceEnded(previous.text)&&row.start-previous.end<=3&&row.start>=previous.end-.05){
   previous.end=row.end;previous.text+=' '+String(row.text||'').trim();
   if(previous.words&&row.words)previous.words.push(...row.words);else delete previous.words;
  }else result.push({...row, ...(row.words?{words:[...row.words]}:{})});
 }
 return result;
}
