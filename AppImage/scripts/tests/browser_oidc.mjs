// Disposable Chrome DevTools flow. No browser automation package required.
import fs from 'node:fs';
const [profile, origin] = process.argv.slice(2);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const deadline = Date.now() + 45000;
while (!fs.existsSync(`${profile}/DevToolsActivePort`)) {
  if (Date.now() > deadline) throw Error('Browser debugging endpoint unavailable');
  await sleep(100);
}
const port = fs.readFileSync(`${profile}/DevToolsActivePort`, 'utf8').split('\n')[0];
const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const socket = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(resolve => socket.addEventListener('open', resolve, {once: true}));
let counter = 0;
const pending = new Map();
socket.addEventListener('message', event => {
  const data = JSON.parse(event.data);
  if (!data.id) return;
  const callbacks = pending.get(data.id); pending.delete(data.id);
  if (data.error) callbacks.reject(Error(data.error.message)); else callbacks.resolve(data.result);
});
function call(method, params={}) {
  const id = ++counter;
  return new Promise((resolve,reject) => {
    pending.set(id,{resolve,reject}); socket.send(JSON.stringify({id,method,params}));
  });
}
async function evaluate(expression) {
  const result = await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
  if (result.exceptionDetails) throw Error('Browser script failed');
  return result.result.value;
}
async function until(expression) {
  while (Date.now() < deadline) {
    try { if (await evaluate(expression)) return; } catch {}
    await sleep(100);
  }
  throw Error('Browser condition timed out');
}
await call('Page.enable');
await call('Runtime.enable');
await call('Page.navigate',{url:origin});
await until(`Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Sign in with Authentik'))`);
await evaluate(`Array.from(document.querySelectorAll('button')).find(b=>b.textContent.includes('Sign in with Authentik')).click()`);
await until(`location.origin===${JSON.stringify(origin)} && !!localStorage.getItem('proxmenux-auth-token')`);
const protectedStatus=await evaluate(`fetch('/api/protected-test',{headers:{Authorization:'Bearer '+localStorage.getItem('proxmenux-auth-token')}}).then(r=>r.status)`);
if(protectedStatus!==200)throw Error('Owner session rejected');
const secretInUrl=await evaluate(`!!location.search || !!location.hash`);
if(secretInUrl)throw Error('Unexpected callback data in landing URL');
// Exercise the existing logout storage semantics, then mobile login rejection.
await evaluate(`localStorage.removeItem('proxmenux-auth-token')`);
const signedOutStatus=await evaluate(`fetch('/api/protected-test').then(r=>r.status)`);
if(signedOutStatus!==401)throw Error('Unauthenticated request accepted');
await evaluate(`fetch('/test/scenario',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:'wrong-owner'})})`);
await call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
await call('Page.navigate',{url:origin});
await until(`Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Sign in with Authentik'))`);
await evaluate(`Array.from(document.querySelectorAll('button')).find(b=>b.textContent.includes('Sign in with Authentik')).click()`);
await until(`document.body.textContent.includes('OIDC sign-in denied')`);
if(await evaluate(`!!localStorage.getItem('proxmenux-auth-token')`))throw Error('Denied identity received session');
await evaluate(`fetch('/test/scenario',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:'owner'})})`);
await call('Page.navigate',{url:origin});
await until(`Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Sign in with Authentik'))`);
await evaluate(`Array.from(document.querySelectorAll('button')).find(b=>b.textContent.includes('Sign in with Authentik')).click()`);
await until(`location.origin===${JSON.stringify(origin)} && !!localStorage.getItem('proxmenux-auth-token')`);
const mobileStatus=await evaluate(`fetch('/api/protected-test',{headers:{Authorization:'Bearer '+localStorage.getItem('proxmenux-auth-token')}}).then(r=>r.status)`);
if(mobileStatus!==200)throw Error('Mobile owner login failed');
console.log(JSON.stringify({desktopOwnerLogin:true,protectedStatus,signedOutStatus,mobileWrongOwnerDenied:true,mobileOwnerLogin:true,landingUrlClean:true}));
await call('Browser.close');
socket.close();
