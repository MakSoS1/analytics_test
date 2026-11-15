import test from 'node:test';
import assert from 'node:assert/strict';

test('the gate and full audit use the same persistent-context entry point and normal launch options',async()=>{
 const {launchAuditBrowser,browserLaunchSettings}=await import('./browser-launch.mjs');
 const calls=[],context={id:'context'};
 const chromium={launchPersistentContext:async(profile,options)=>{calls.push({profile,options});return context},
  launch:()=>{throw Error('A nonpersistent control must not replace the full persistent retry')}};
 assert.equal(await launchAuditBrowser(chromium,'/private/fresh-smoke-profile'),context);
 assert.equal(await launchAuditBrowser(chromium,'/private/fresh-case-profile'),context);
 assert.deepEqual(calls[0].options,calls[1].options);
 assert.deepEqual(calls[0].options,{channel:'chrome',headless:true,acceptDownloads:true,serviceWorkers:'block',viewport:{width:1440,height:1000},
  args:['--no-sandbox','--disable-dev-shm-usage','--disable-background-timer-throttling','--disable-renderer-backgrounding']});
 const mutable=browserLaunchSettings();mutable.args.push('--unwanted-override');mutable.viewport.width=1;
 assert.deepEqual(browserLaunchSettings(),calls[0].options);
});

test('the diagnostic control keeps the same four launch flags and context options in a fresh nonpersistent browser',async()=>{
 const {launchDiagnosticBrowser,browserLaunchSettings}=await import('./browser-launch.mjs');
 const calls=[],context={id:'control'};
 const browser={newContext:async options=>{calls.push({kind:'context',options});return context},close:async()=>calls.push({kind:'close'})};
 const chromium={launch:async options=>{calls.push({kind:'launch',options});return browser}};
 const control=await launchDiagnosticBrowser(chromium);assert.equal(control.context,context);await control.close();
 const settings=browserLaunchSettings();
 assert.deepEqual(calls,[{kind:'launch',options:{channel:settings.channel,headless:settings.headless,args:settings.args}},
  {kind:'context',options:{acceptDownloads:settings.acceptDownloads,serviceWorkers:settings.serviceWorkers,viewport:settings.viewport}},
  {kind:'close'}]);
});
