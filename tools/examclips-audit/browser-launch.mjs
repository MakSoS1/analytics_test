// The retry keeps the full-case persistent Chrome mode and existing launch options.
// Its preparation ASR gate calls this same entry point with a separate fresh profile.
export const browserLaunchSettings=()=>({
 channel:'chrome',headless:true,acceptDownloads:true,serviceWorkers:'block',viewport:{width:1440,height:1000},
 args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-timer-throttling','--disable-renderer-backgrounding']
});

export const launchAuditBrowser=(chromium,profile)=>chromium.launchPersistentContext(profile,browserLaunchSettings());

export async function launchDiagnosticBrowser(chromium){
 const {channel,headless,args,acceptDownloads,serviceWorkers,viewport}=browserLaunchSettings();
 const browser=await chromium.launch({channel,headless,args});
 try{
  const context=await browser.newContext({acceptDownloads,serviceWorkers,viewport});
  return {context,browser,close:()=>browser.close()};
 }catch(error){await browser.close().catch(()=>{});throw error}
}
