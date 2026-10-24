/** Conservative silence detector. Avoid Whisper hallucinations from digitally blank audio.
 * Extremely quiet, but non-zero, speech is deliberately NOT aggressively rejected.
 */
export function isSilent(pcm, rmsThreshold=0.00012, peakThreshold=0.0008){
  if(!(pcm instanceof Float32Array)||pcm.length===0)return true;
  let squares=0,peak=0;
  for(let i=0;i<pcm.length;i++){const x=Number.isFinite(pcm[i])?pcm[i]:0;peak=Math.max(peak,Math.abs(x));squares+=x*x}
  return peak<peakThreshold && Math.sqrt(squares/pcm.length)<rmsThreshold;
}
