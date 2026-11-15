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
