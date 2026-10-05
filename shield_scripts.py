"""
shield_scripts.py: JavaScript that Shield injects into pages. No Qt in here, so the scripts can be syntax-checked
and run under Node in the tests.

  FP_JS     fingerprint protection. Runs in the page's own world because it has to change what the page sees.
  VAULT_JS  finds login forms, reports submitted logins to the browser and fills logins the user picked.
            Runs in an isolated world: the page's scripts cannot see it, call it or read its variables.
  YT_JS     removes YouTube's video ads from the data the player is given. youtube.com only, page's own world.
"""

# --------------------------------------------------------------------------
# Fingerprint protection
# --------------------------------------------------------------------------
# Standard: hardware hints are normalised, and canvas, WebGL read-back and audio output get tiny noise.
# Strict adds generic WebGL strings and rounds the screen size.
# The noise is seeded per *site*: the same site sees the same values all session (so nothing breaks), but two
# sites can't compare notes to recognise you. Every patched function reports itself as native code.
FP_JS = r"""
(()=>{
const SECRET="__SECRET__",STRICT="__LEVEL__"==="strict";
const sec=f=>{try{f()}catch(e){}};
const topHost=(()=>{try{const a=location.ancestorOrigins;if(a&&a.length)return new URL(a[a.length-1]).hostname}catch(e){}return location.hostname})()||"";
const reg=h=>{const p=h.split(".");if(p.length<=2)return h;const l=p.slice(-2).join(".");return/^(co|com|org|net|gov|ac|edu)\.[a-z]{2}$/.test(l)?p.slice(-3).join("."):l};
const fnv=s=>{let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return h>>>0};
const seed=fnv(SECRET+"|"+reg(topHost));
const rnd=n=>{let x=(seed^Math.imul(n+1,2654435761))>>>0;x^=x<<13;x>>>=0;x^=x>>>17;x^=x<<5;x>>>=0;return x/4294967296};

// every patched function answers toString() like a native one
const natives=new WeakMap();
sec(()=>{
 const ts=Function.prototype.toString;
 const tsp=function toString(){const n=natives.get(this);return n!==undefined?n:ts.call(this)};
 natives.set(tsp,"function toString() { [native code] }");
 Object.defineProperty(Function.prototype,"toString",{value:tsp,writable:true,configurable:true});
});
const mask=(fn,name)=>{natives.set(fn,"function "+name+"() { [native code] }");try{Object.defineProperty(fn,"name",{value:name,configurable:true})}catch(e){}return fn};
const getter=(o,p,v)=>{try{Object.defineProperty(o,p,{get:mask(function(){return typeof v==="function"?v():v},"get "+p),configurable:true,enumerable:true})}catch(e){}};
const patch=(o,name,make)=>{try{const orig=o[name];if(typeof orig!=="function")return;o[name]=mask(make(orig),name)}catch(e){}};

// hardware and language hints
sec(()=>{
 getter(Navigator.prototype,"hardwareConcurrency",4);
 getter(Navigator.prototype,"deviceMemory",8);
 const langs=Object.freeze(["en-US","en"]);
 getter(Navigator.prototype,"languages",()=>langs);
 getter(Navigator.prototype,"language","en-US");
});
sec(()=>{if(window.NavigatorUAData)patch(NavigatorUAData.prototype,"getHighEntropyValues",o=>function getHighEntropyValues(h){return o.call(this,[])})});

// screen
sec(()=>{
 getter(Screen.prototype,"colorDepth",24);getter(Screen.prototype,"pixelDepth",24);
 if(STRICT){const r=v=>Math.round(v/100)*100;
  for(const p of["width","height","availWidth","availHeight"]){const d=Object.getOwnPropertyDescriptor(Screen.prototype,p);if(d&&d.get){const g=d.get;getter(Screen.prototype,p,function(){return r(g.call(screen))})}}}
});

// canvas
const gid=window.CanvasRenderingContext2D&&CanvasRenderingContext2D.prototype.getImageData;
const farble=d=>{for(let i=0;i<d.length;i+=388){const k=Math.floor(rnd(i)*3);d[i+k]=d[i+k]^1}return d};
sec(()=>{
 const types=new WeakMap();
 patch(HTMLCanvasElement.prototype,"getContext",o=>function getContext(t,...a){const r=o.call(this,t,...a);if(r&&!types.has(this))types.set(this,String(t));return r});
 patch(CanvasRenderingContext2D.prototype,"getImageData",o=>function getImageData(...a){const r=o.apply(this,a);try{farble(r.data)}catch(e){}return r});
 for(const name of["toDataURL","toBlob"]){
  patch(HTMLCanvasElement.prototype,name,o=>function(...a){
   if(types.get(this)==="2d"&&this.width*this.height>0&&this.width*this.height<4e6){
    try{const c=document.createElement("canvas");c.width=this.width;c.height=this.height;const x=c.getContext("2d");
     x.drawImage(this,0,0);const im=gid.call(x,0,0,c.width,c.height);farble(im.data);x.putImageData(im,0,0);return o.apply(c,a)}catch(e){}}
   return o.apply(this,a)})}
});

// WebGL: read-back noise always, vendor and renderer strings only in strict mode
sec(()=>{
 for(const P of[window.WebGLRenderingContext,window.WebGL2RenderingContext]){
  if(!P)continue;
  patch(P.prototype,"readPixels",o=>function readPixels(...a){const r=o.apply(this,a);try{const px=a[a.length-1];if(px&&px.BYTES_PER_ELEMENT===1&&px.length)for(let i=0;i<px.length;i+=389)px[i]=px[i]^1}catch(e){}return r});
  if(STRICT)patch(P.prototype,"getParameter",o=>function getParameter(p){if(p===37445)return"Google Inc.";if(p===37446)return"ANGLE (Generic Renderer)";return o.call(this,p)});
 }
});

// audio
sec(()=>{
 if(window.AudioBuffer){const done=new WeakSet();
  patch(AudioBuffer.prototype,"getChannelData",o=>function getChannelData(c){const d=o.call(this,c);if(!done.has(d)){done.add(d);try{for(let i=0;i<d.length;i+=97)d[i]+=(rnd(i)-.5)*2e-7}catch(e){}}return d})}
 if(window.AnalyserNode){
  patch(AnalyserNode.prototype,"getFloatFrequencyData",o=>function getFloatFrequencyData(a){o.call(this,a);try{for(let i=0;i<a.length;i+=7)a[i]+=(rnd(i)-.5)*.2}catch(e){}});
  patch(AnalyserNode.prototype,"getByteFrequencyData",o=>function getByteFrequencyData(a){o.call(this,a);try{for(let i=0;i<a.length;i+=11)a[i]=a[i]^1}catch(e){}})}
});
})();
"""

# --------------------------------------------------------------------------
# Password forms
# --------------------------------------------------------------------------
# The browser prepends Qt's qwebchannel.js. Only the top frame is handled on purpose: a login form hidden inside a
# third-party iframe is how credential-stealing overlays work, so it is never reported and never filled.
VAULT_JS = r"""
(()=>{
if(!/^https?:$/.test(location.protocol)||window.top!==window||window.__shieldVault)return;
window.__shieldVault=1;
if(typeof QWebChannel==="undefined"||typeof qt==="undefined"||!qt.webChannelTransport)return;
let bridge=null,timer=0,lastSeen="",lastSent="",lastAt=0;
const send=(m,o)=>{try{if(bridge)bridge[m](JSON.stringify(o))}catch(e){}};
const vis=e=>{try{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>2&&r.height>2&&s.visibility!=="hidden"&&s.display!=="none"&&s.opacity!=="0"}catch(x){return false}};
const passFields=()=>[...document.querySelectorAll("input[type=password]")].filter(vis);
const userField=p=>{
 const scope=p.form||document;
 const c=[...scope.querySelectorAll("input")].filter(i=>i!==p&&vis(i)&&!i.disabled&&!i.readOnly&&/^(text|email|tel|url|)$/i.test(i.getAttribute("type")||""));
 let best=null;for(const i of c){if(i.compareDocumentPosition(p)&Node.DOCUMENT_POSITION_FOLLOWING)best=i}
 return best};
const actionOrigin=p=>{try{const f=p.form;const a=f&&f.getAttribute("action");return a?new URL(a,location.href).origin:location.origin}catch(e){return location.origin}};
const isNew=ps=>ps.length>=2||ps.some(p=>(p.autocomplete||"").toLowerCase()==="new-password");

const report=()=>{
 const ps=passFields();
 const d={pw:ps.length>0,newpw:ps.length?isNew(ps):false,user:ps.length?!!userField(ps[0]):false,cross:ps.length?actionOrigin(ps[0])!==location.origin:false};
 const k=JSON.stringify(d);if(k===lastSeen)return;lastSeen=k;send("seen",d)};
const later=()=>{clearTimeout(timer);timer=setTimeout(report,450)};

// Only real user actions count. A page can fire fake submit, click and Enter events at will; without this check it
// could make Shield pop up save prompts for logins the person never sent, or time them to confuse the person.
const real=e=>e&&e.isTrusted===true;
const capture=()=>{
 const ps=passFields();if(!ps.length)return;
 let kind="login",pw=ps[0].value,old="";
 if(ps.length>=3&&ps[1].value&&ps[1].value===ps[2].value){kind="change";old=ps[0].value;pw=ps[1].value}
 else if(ps.length===2&&ps[0].value&&ps[0].value===ps[1].value){kind="new";pw=ps[0].value}
 else if(ps.length>=2){return}
 if(!pw||pw.length>256)return;
 const u=userField(ps[0]);
 const d={kind:kind,user:u?u.value.slice(0,256):"",pw:pw,old:old,cross:actionOrigin(ps[0])!==location.origin};
 const k=JSON.stringify(d),now=Date.now();
 if(k===lastSent&&now-lastAt<2500)return;lastSent=k;lastAt=now;send("captured",d)};

document.addEventListener("submit",e=>{if(real(e)&&e.target&&e.target.querySelector&&e.target.querySelector("input[type=password]"))capture()},true);
document.addEventListener("click",e=>{
 if(!real(e))return;
 const t=e.target&&e.target.closest&&e.target.closest("button,input[type=submit],input[type=image],[role=button]");
 if(!t)return;const f=t.form||t.closest("form")||document;
 if(f.querySelector&&f.querySelector("input[type=password]")&&(t.type==="submit"||t.tagName==="BUTTON"||t.getAttribute("role")==="button"))capture()},true);
document.addEventListener("keydown",e=>{
 if(!real(e)||e.key!=="Enter"||!e.target||e.target.tagName!=="INPUT")return;
 const ps=passFields();if(!ps.length)return;
 if(ps.includes(e.target)||(e.target.form&&e.target.form===ps[0].form))capture()},true);

// A field a person can actually see and click: big enough, on screen, not faded out, not covered by something else.
// Invisible or covered password fields are how pages harvest autofilled logins without the person noticing.
const seen=e=>{
 try{
  if(!vis(e))return false;
  const r=e.getBoundingClientRect(),s=getComputedStyle(e);
  if(r.width<20||r.height<10||parseFloat(s.opacity)<.5||s.pointerEvents==="none")return false;
  if(r.bottom<=0||r.right<=0||r.top>=innerHeight||r.left>=innerWidth)return false;
  const x=Math.min(Math.max(r.left+r.width/2,0),innerWidth-1),y=Math.min(Math.max(r.top+r.height/2,0),innerHeight-1);
  const top=document.elementFromPoint(x,y);
  if(!top)return false;
  if(top===e||e.contains(top)||top.contains(e))return true;
  const lab=e.labels&&[...e.labels].some(l=>l===top||l.contains(top));
  return !!lab;
 }catch(x){return false}};
// Fill: called by the browser, only after the person picked a login from the key menu.
window.__shieldFill=(user,pw)=>{
 const ps=passFields();if(!ps.length)return"noform";
 const p=ps.find(seen);
 if(!p)return"hidden";
 if(actionOrigin(p)!==location.origin)return"cross";
 const set=(el,v)=>{const d=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value");d.set.call(el,v);el.dispatchEvent(new Event("input",{bubbles:true}));el.dispatchEvent(new Event("change",{bubbles:true}))};
 const u=userField(p);
 if(u&&user&&seen(u))set(u,user);
 set(p,pw);
 return"ok"};

const start=()=>{
 new QWebChannel(qt.webChannelTransport,ch=>{
  bridge=ch.objects.shieldVault;
  report();
  new MutationObserver(later).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:["type","style","class","hidden"]});
  addEventListener("pageshow",later);
 })};
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",start,{once:true});else start();
})();
"""


# --------------------------------------------------------------------------
# YouTube ads
# --------------------------------------------------------------------------
# YouTube serves its ads from the same servers as the video, so a request filter cannot tell them apart. What does
# work is changing the data the player is given: the player is handed a JSON document that lists the ads to play
# ("adPlacements", "playerAds", "adSlots"), and removing those keys before the player reads them means it plays no ads.
# This is the same technique the uBlock Origin lists use for YouTube, but as one fixed script written here: filter
# lists can never supply code to run, they only supply addresses and page-hiding selectors.
#   1. The page's first player data (window.ytInitialPlayerResponse) and every later one (fetch, XHR, JSON.parse
#      for the player, next-video and Shorts requests) is stripped of its ad lists.
#   2. The "ad blockers are not allowed" dialog and its Premium upsell are removed before they can show.
#   3. Page-hiding rules cover the ad boxes that are not part of the video (home-page ads, banners, side ads).
#   4. A safety net: if an ad still starts playing, it is muted, sped up to the maximum and its skip button is
#      pressed, then the person's own volume and speed are put back. It never seeks, so it cannot cut a real video short.
# Runs only on youtube.com, in the page's own world (it has to change what the player sees), once per page load.
YT_JS = r"""
(()=>{
const H=(location.hostname||"").toLowerCase();
if(!/(^|\.)youtube\.com$/.test(H))return;
const sec=f=>{try{f()}catch(e){}};
const origParse=JSON.parse;

// patched functions answer toString() like native ones
const nat=new WeakMap();
sec(()=>{
 const ts=Function.prototype.toString;
 const tsp=function toString(){const n=nat.get(this);return n!==undefined?n:ts.call(this)};
 nat.set(tsp,"function toString() { [native code] }");
 Object.defineProperty(Function.prototype,"toString",{value:tsp,writable:true,configurable:true});
});
const mask=(fn,name)=>{nat.set(fn,"function "+name+"() { [native code] }");try{Object.defineProperty(fn,"name",{value:name,configurable:true})}catch(e){}return fn};

// 1. strip the ad lists out of player data
const AD_KEYS=["adPlacements","playerAds","adSlots"];
const NAGS=["enforcementMessageViewModel","upsellDialogRenderer"];
const strip=o=>{
 for(const k of AD_KEYS)if(k in o){try{delete o[k]}catch(e){}}
 const m=o.auxiliaryUi&&o.auxiliaryUi.messageRenderers;
 if(m&&typeof m==="object")for(const k of NAGS)if(k in m){try{delete m[k]}catch(e){}}
};
const isAdEntry=e=>{const a=e&&e.command&&e.command.reelWatchEndpoint&&e.command.reelWatchEndpoint.adClientParams;return !!(a&&a.isAd)};
const prune=o=>{
 try{
  if(!o||typeof o!=="object"||Array.isArray(o))return o;
  strip(o);
  const pr=o.playerResponse;
  if(pr&&typeof pr==="object")strip(pr);
  if(Array.isArray(o.entries)&&o.entries.some(isAdEntry))o.entries=o.entries.filter(e=>!isAdEntry(e));
 }catch(e){}
 return o};
const looksLikePlayerData=x=>"adPlacements" in x||"playerAds" in x||"adSlots" in x||"playerResponse" in x||"entries" in x||"auxiliaryUi" in x;
const isApi=u=>/\/youtubei\/v1\/(player|next|reel\/|get_watch)/.test(String(u||""));

// the data the page itself starts with
sec(()=>{
 let v;
 Object.defineProperty(window,"ytInitialPlayerResponse",{configurable:true,enumerable:true,
  get:mask(function(){return v},"get ytInitialPlayerResponse"),
  set:mask(function(x){v=prune(x)},"set ytInitialPlayerResponse")});
});
// data parsed from text
sec(()=>{
 JSON.parse=mask(function parse(){
  const x=origParse.apply(this,arguments);
  if(x&&typeof x==="object"&&!Array.isArray(x)&&looksLikePlayerData(x))prune(x);
  return x},"parse");
});
// fetch
sec(()=>{
 const oj=Response.prototype.json;
 Response.prototype.json=mask(function json(){
  const url=this.url;
  return oj.call(this).then(x=>{try{if(isApi(url))prune(x)}catch(e){}return x})},"json");
});
// XMLHttpRequest
sec(()=>{
 const X=XMLHttpRequest.prototype,urls=new WeakMap(),cache=new WeakMap();
 const oo=X.open;
 X.open=mask(function open(m,u){try{urls.set(this,String(u))}catch(e){}return oo.apply(this,arguments)},"open");
 const rewrite=(x,v)=>{
  const u=urls.get(x);
  if(!u||!isApi(u)||x.readyState!==4)return v;
  if(v&&typeof v==="object"){prune(v);return v}
  if(typeof v!=="string")return v;
  const c=cache.get(x);if(c&&c.src===v)return c.out;
  let out=v;
  try{const j=origParse.call(JSON,v);prune(j);out=JSON.stringify(j)}catch(e){}
  cache.set(x,{src:v,out});return out};
 for(const p of["responseText","response"]){
  const d=Object.getOwnPropertyDescriptor(X,p);
  if(!d||!d.get)continue;
  const g=d.get;
  Object.defineProperty(X,p,{configurable:true,enumerable:d.enumerable,get:mask(function(){return rewrite(this,g.call(this))},"get "+p)});
 }
});

// 3. hide the ad boxes that are not part of the video
const HIDE=["#masthead-ad","#player-ads","ytd-ad-slot-renderer","ytd-in-feed-ad-layout-renderer","ytd-promoted-sparkles-web-renderer",
 "ytd-display-ad-renderer","ytd-banner-promo-renderer","ytd-statement-banner-renderer","ytd-companion-slot-renderer",
 "ytd-player-legacy-desktop-watch-ads-renderer","ytd-enforcement-message-view-model",".ytp-ad-overlay-container",
 ".ytp-ad-overlay-slot","[target-id=engagement-panel-ads]"];
const HIDE_HAS=["ytd-rich-item-renderer:has(ytd-ad-slot-renderer)","tp-yt-paper-dialog:has(ytd-enforcement-message-view-model)"];
sec(()=>{
 const css=HIDE.join(",")+"{display:none!important}\n"+HIDE_HAS.join(",")+"{display:none!important}";   // :has() in its own rule so an old engine cannot void the first
 const go=()=>{
  try{const sh=new CSSStyleSheet();sh.replaceSync(css);document.adoptedStyleSheets=[...document.adoptedStyleSheets,sh];return}catch(e){}
  const st=document.createElement("style");st.textContent=css;(document.head||document.documentElement).appendChild(st)};
 if(document.documentElement)go();
 else new MutationObserver((_,o)=>{if(document.documentElement){o.disconnect();go()}}).observe(document,{childList:true});
});

// 2 and 4. the blocker dialog, and the safety net for an ad that still starts
const q=(root,s)=>{try{return root.querySelector(s)}catch(e){return null}};
let saved=null,savedVideo=null;
const tick=()=>{
 try{
  const nag=q(document,"ytd-enforcement-message-view-model");
  if(nag){
   const bd=q(document,"tp-yt-iron-overlay-backdrop");
   nag.remove();if(bd)bd.remove();
   const vid=q(document,"video");
   if(vid&&vid.paused){const p=vid.play();if(p&&p.catch)p.catch(()=>{})}
  }
  const player=q(document,".html5-video-player");
  const video=player&&(q(player,"video.html5-main-video")||q(player,"video"));
  if(player&&video&&player.classList.contains("ad-showing")){
   if(!saved){saved={rate:video.playbackRate,muted:video.muted};savedVideo=video}
   video.muted=true;
   try{video.playbackRate=16}catch(e){}
   const skip=q(player,".ytp-skip-ad-button,.ytp-ad-skip-button,.ytp-ad-skip-button-modern");
   if(skip)skip.click();
   const close=q(player,".ytp-ad-overlay-close-button");
   if(close)close.click();
  }else if(saved){
   const v=savedVideo||video;
   if(v){try{v.playbackRate=saved.rate;v.muted=saved.muted}catch(e){}}
   saved=null;savedVideo=null;
  }
 }catch(e){}
};
setInterval(tick,250);
})();
"""


def fp_script(secret, level):
    """The fingerprint script with this session's secret and the chosen level filled in."""
    level = "strict" if level == "strict" else "standard"
    return FP_JS.replace("__SECRET__", str(secret)).replace("__LEVEL__", level)


def fill_call(user, password):
    """JavaScript that fills the form in the isolated world. json.dumps makes both strings safe to embed."""
    import json
    return f"window.__shieldFill({json.dumps(user)},{json.dumps(password)})"


def is_youtube_host(host):
    """True for youtube.com and its subdomains (www, m, music...). Nothing else gets the YouTube script."""
    host = (host or "").lower().strip(".")
    return host == "youtube.com" or host.endswith(".youtube.com")
