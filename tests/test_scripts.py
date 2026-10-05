"""Syntax-checks and exercises the injected scripts under Node (skipped when Node isn't installed)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shield_scripts as S  # noqa: E402

NODE = shutil.which("node")


def run_js(code):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        return subprocess.run([NODE, path], capture_output=True, text=True, timeout=30)
    finally:
        os.unlink(path)


HARNESS = r"""
const g=globalThis;
g.window=g;
g.location={hostname:"%HOST%",protocol:"https:",href:"https://%HOST%/",origin:"https://%HOST%"};
class Navigator{} Object.defineProperty(g,"Navigator",{value:Navigator,configurable:true,writable:true}); Object.defineProperty(g,"navigator",{value:new Navigator(),configurable:true,writable:true});
class Screen{get width(){return 1366}get height(){return 768}get availWidth(){return 1366}get availHeight(){return 728}get colorDepth(){return 30}get pixelDepth(){return 30}} g.Screen=Screen; g.screen=new Screen();
class HTMLCanvasElement{getContext(t){return {}} toDataURL(){return "data:real"} toBlob(){}} g.HTMLCanvasElement=HTMLCanvasElement;
class CanvasRenderingContext2D{getImageData(){return {data:new Uint8ClampedArray(2000)}}} g.CanvasRenderingContext2D=CanvasRenderingContext2D;
class WebGLRenderingContext{getParameter(p){return "real-"+p} readPixels(x,y,w,h,f,t,px){px.fill(100)}} g.WebGLRenderingContext=WebGLRenderingContext;
class AudioBuffer{constructor(){this.d=new Float32Array(1000)} getChannelData(){return this.d}} g.AudioBuffer=AudioBuffer;
class AnalyserNode{getFloatFrequencyData(a){a.fill(-50)} getByteFrequencyData(a){a.fill(100)}} g.AnalyserNode=AnalyserNode;
g.document={createElement(){return {getContext(){return {drawImage(){},putImageData(){}}}}}};
%SCRIPT%
const out={};
out.cores=navigator.hardwareConcurrency;out.lang=navigator.languages.join();out.depth=screen.colorDepth;
out.w=screen.width;
const ab=new AudioBuffer();ab.getChannelData(0);out.audioNoisy=Array.from(ab.d).some(v=>v!==0);
const px=new Uint8Array(1000);new WebGLRenderingContext().readPixels(0,0,1,1,0,0,px);out.glNoisy=px.some(v=>v!==100);
out.vendor=new WebGLRenderingContext().getParameter(37445);
const im=new CanvasRenderingContext2D().getImageData();out.canvasNoisy=Array.from(im.data).some(v=>v!==0);
out.sig=Array.from(im.data).map((v,i)=>v?i:-1).filter(i=>i>=0).join(",")+"|"+Array.from(px).map((v,i)=>v!==100?i:-1).filter(i=>i>=0).join(",");
const fn=Function.prototype.toString.call(HTMLCanvasElement.prototype.getContext);
out.nativeLooking=/native code/.test(fn);
out.tsSelf=/native code/.test(Function.prototype.toString.call(Function.prototype.toString));
out.plainFn=Function.prototype.toString.call(function foo(){return 1}).includes("return 1");
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node is not installed")
class FingerprintScript(unittest.TestCase):
    def run_fp(self, host="a.example.com", level="standard", secret="s3cr3t"):
        code = HARNESS.replace("%HOST%", host).replace("%SCRIPT%", S.fp_script(secret, level))
        r = run_js(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_standard(self):
        o = self.run_fp()
        self.assertEqual((o["cores"], o["lang"], o["depth"], o["w"]), (4, "en-US,en", 24, 1366))
        self.assertTrue(o["audioNoisy"] and o["glNoisy"] and o["canvasNoisy"])
        self.assertEqual(o["vendor"], "real-37445")          # standard leaves the GPU strings alone
        self.assertTrue(o["nativeLooking"] and o["tsSelf"] and o["plainFn"])

    def test_strict(self):
        o = self.run_fp(level="strict")
        self.assertEqual(o["vendor"], "Google Inc.")
        self.assertEqual(o["w"], 1400)

    def test_per_site_seed(self):
        a = self.run_fp(host="shop.example.com")["sig"]
        b = self.run_fp(host="www.example.com")["sig"]       # same registrable site: same noise
        c = self.run_fp(host="other.org")["sig"]
        d = self.run_fp(host="shop.example.com", secret="another session")["sig"]
        self.assertEqual(a, b)
        self.assertNotEqual(a, d)
        self.assertTrue(c)

    def test_level_is_validated(self):
        self.assertIn('"standard"==="strict"', S.fp_script("x", "evil\"+alert(1)+\""))


@unittest.skipUnless(NODE, "node is not installed")
class SyntaxChecks(unittest.TestCase):
    def check(self, name, code):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            r = subprocess.run([NODE, "--check", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")
        finally:
            os.unlink(path)

    def test_scripts(self):
        self.check("fp", S.fp_script("x", "standard"))
        self.check("vault", S.VAULT_JS)

    def test_fill_call_escapes(self):
        call = S.fill_call('a"b\u2028', "p\\w'</script>")
        self.check("fill", call)
        self.assertIn('\\"', call)


@unittest.skipUnless(NODE, "node is not installed")
class VaultScript(unittest.TestCase):
    """Run the content script against a tiny fake DOM and check what it reports."""

    def test_reports_and_capture(self):
        code = r"""
const sent=[];let handlers={};
const mk=(o)=>Object.assign({getBoundingClientRect(){return{width:100,height:20}},getAttribute(k){return this.attrs&&this.attrs[k]||null},compareDocumentPosition(){return 4},closest(){return null},dispatchEvent(){return true}},o);
const user=mk({type:"email",value:"ann@example.com",tagName:"INPUT",disabled:false,readOnly:false,attrs:{type:"email"}});
const pw=mk({type:"password",value:"hunter2hunter2",tagName:"INPUT",autocomplete:"",attrs:{type:"password"}});
const form=mk({querySelectorAll(sel){return sel==="input"?[user,pw]:[]},querySelector(sel){return sel.includes("password")?pw:null},getAttribute(){return null},contains(){return true}});
user.form=form;pw.form=form;
globalThis.window=globalThis;window.top=window;
globalThis.location={protocol:"https:",href:"https://a.example/login",origin:"https://a.example"};
globalThis.getComputedStyle=()=>({visibility:"visible",display:"block",opacity:"1"});
globalThis.Node={DOCUMENT_POSITION_FOLLOWING:4};
globalThis.Event=class{constructor(t){this.type=t}};
globalThis.HTMLInputElement={prototype:{}};
Object.defineProperty(HTMLInputElement.prototype,"value",{set(v){this._v=v}});
globalThis.URL=URL;
globalThis.document={readyState:"complete",documentElement:{},
 querySelectorAll(sel){return sel==="input[type=password]"?[pw]:[]},
 addEventListener(t,f){handlers[t]=f}};
globalThis.MutationObserver=class{observe(){}};
globalThis.addEventListener=()=>{};
globalThis.qt={webChannelTransport:{}};
globalThis.QWebChannel=class{constructor(t,cb){cb({objects:{shieldVault:{seen(s){sent.push(["seen",JSON.parse(s)])},captured(s){sent.push(["captured",JSON.parse(s)])}}}})}};
%SCRIPT%
handlers.submit({target:form});
const r=window.__shieldFill("bob","newpw");
console.log(JSON.stringify({sent,fill:r,pwSet:pw._v,userSet:user._v}));
""".replace("%SCRIPT%", S.VAULT_JS)
        r = run_js(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout.strip().splitlines()[-1])
        kinds = [k for k, _ in out["sent"]]
        self.assertEqual(kinds, ["seen", "captured"])
        seen, cap = out["sent"][0][1], out["sent"][1][1]
        self.assertTrue(seen["pw"] and seen["user"] and not seen["newpw"] and not seen["cross"])
        self.assertEqual((cap["kind"], cap["user"], cap["pw"]), ("login", "ann@example.com", "hunter2hunter2"))
        self.assertEqual((out["fill"], out["pwSet"], out["userSet"]), ("ok", "newpw", "bob"))


YT_HARNESS = r"""
const g=globalThis;
g.window=g;
g.location={hostname:"%HOST%",protocol:"https:"};
const state={ad:false,nag:false,removed:[],skipClicks:0,closeClicks:0,played:0};
const video={playbackRate:1.5,muted:false,paused:true,currentTime:5,play(){state.played++;return Promise.resolve()}};
const skipBtn={click(){state.skipClicks++}};
const player={classList:{contains:c=>c==="ad-showing"&&state.ad},
 querySelector(sel){
  if(sel==="video.html5-main-video"||sel==="video")return video;
  if(sel.includes("ytp-skip-ad-button"))return state.ad?skipBtn:null;
  if(sel.includes("ytp-ad-overlay-close-button"))return null;
  return null}};
const nagEl={remove(){state.removed.push("nag")}},backdrop={remove(){state.removed.push("backdrop")}};
g.document={documentElement:{},head:{appendChild(){}},createElement(){return{}},
 querySelector(sel){
  if(sel===".html5-video-player")return player;
  if(sel==="ytd-enforcement-message-view-model")return state.nag?nagEl:null;
  if(sel==="tp-yt-iron-overlay-backdrop")return state.nag?backdrop:null;
  if(sel==="video")return video;
  return null}};
g.MutationObserver=class{observe(){}};
let timer=()=>{};
g.setInterval=(f)=>{timer=f;return 1};
class XMLHttpRequest{open(m,u){this.u=u} get responseText(){return this._t} get response(){return this._t}}
g.XMLHttpRequest=XMLHttpRequest;
const rawParse=JSON.parse;
%SCRIPT%
const ADS=()=>({adPlacements:[1],playerAds:[1],adSlots:[1],videoDetails:{id:"abc"},streamingData:{x:1}});
const out={};
(async()=>{
 out.parsePatched=JSON.parse!==rawParse;
 // first player data
 window.ytInitialPlayerResponse=Object.assign(ADS(),{auxiliaryUi:{messageRenderers:{enforcementMessageViewModel:{a:1},keepMe:{b:2}}}});
 const r=window.ytInitialPlayerResponse;
 out.init={ads:["adPlacements","playerAds","adSlots"].some(k=>k in r),keeps:!!(r.videoDetails&&r.streamingData),nag:"enforcementMessageViewModel" in r.auxiliaryUi.messageRenderers,keepMe:"keepMe" in r.auxiliaryUi.messageRenderers};
 // JSON.parse
 const pr=JSON.parse(JSON.stringify({playerResponse:ADS(),other:1}));
 out.parse={ads:"adPlacements" in pr.playerResponse,keeps:!!pr.playerResponse.videoDetails&&pr.other===1};
 out.plain=JSON.stringify(JSON.parse('{"a":[1,2],"b":{"c":3}}'));
 out.arr=JSON.stringify(JSON.parse('[{"adPlacements":[1]}]'));
 out.reviver=JSON.parse('{"n":1}',(k,v)=>typeof v==="number"?v+1:v).n;
 // fetch
 const mk=(url,obj)=>{const x=new Response(JSON.stringify(obj));Object.defineProperty(x,"url",{value:url});return x};
 const f1=await mk("https://www.youtube.com/youtubei/v1/player?prettyPrint=false",ADS()).json();
 const f2=await mk("https://www.youtube.com/youtubei/v1/next",{playerResponse:ADS()}).json();
 const f4=await mk("https://www.youtube.com/youtubei/v1/reel/reel_watch_sequence",{entries:[{command:{reelWatchEndpoint:{adClientParams:{isAd:true}}}},{command:{reelWatchEndpoint:{videoId:"v1"}}}]}).json();
 out.fetch={player:"adPlacements" in f1,next:"adPlacements" in f2.playerResponse,reel:f4.entries.length,reelKept:f4.entries[0].command.reelWatchEndpoint.videoId};
 // XHR
 const x=new XMLHttpRequest();x.open("POST","https://www.youtube.com/youtubei/v1/player");x.readyState=4;x._t=JSON.stringify(ADS());
 const xr=rawParse(x.responseText);
 out.xhr={ads:"adPlacements" in xr,keeps:!!xr.videoDetails,sameTwice:x.responseText===x.responseText};
 const x2=new XMLHttpRequest();x2.open("GET","https://www.youtube.com/s/player/base.js");x2.readyState=4;x2._t=JSON.stringify(ADS());
 out.xhrOther="adPlacements" in rawParse(x2.responseText);
 const x3=new XMLHttpRequest();x3.open("POST","https://www.youtube.com/youtubei/v1/player");x3.readyState=3;x3._t="partial{";
 out.xhrPartial=x3.responseText;
 // native look
 out.native=/native code/.test(Function.prototype.toString.call(JSON.parse))&&/native code/.test(Function.prototype.toString.call(Response.prototype.json));
 // safety net
 state.ad=true;timer();
 out.ad={muted:video.muted,rate:video.playbackRate,skips:state.skipClicks,time:video.currentTime};
 state.ad=false;timer();
 out.after={muted:video.muted,rate:video.playbackRate,time:video.currentTime};
 // blocker dialog
 state.nag=true;timer();
 out.nag={removed:state.removed.join(),played:state.played};
 console.log(JSON.stringify(out));
})();
"""


@unittest.skipUnless(NODE, "node is not installed")
class YouTubeScript(unittest.TestCase):
    def run_yt(self, host="www.youtube.com"):
        code = YT_HARNESS.replace("%HOST%", host).replace("%SCRIPT%", S.YT_JS)
        r = run_js(code)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_ads_are_stripped_everywhere_the_player_gets_data(self):
        o = self.run_yt()
        self.assertEqual(o["init"], {"ads": False, "keeps": True, "nag": False, "keepMe": True})
        self.assertEqual(o["parse"], {"ads": False, "keeps": True})
        self.assertEqual(o["fetch"], {"player": False, "next": False, "reel": 1, "reelKept": "v1"})
        self.assertEqual(o["xhr"], {"ads": False, "keeps": True, "sameTwice": True})

    def test_everything_else_is_left_alone(self):
        o = self.run_yt()
        self.assertEqual(o["plain"], '{"a":[1,2],"b":{"c":3}}')
        self.assertEqual(o["arr"], '[{"adPlacements":[1]}]')
        self.assertEqual(o["reviver"], 2)                     # JSON.parse still honours a reviver
        self.assertTrue(o["xhrOther"])                        # not a player request: untouched
        self.assertEqual(o["xhrPartial"], "partial{")         # unfinished download: untouched
        self.assertTrue(o["native"])

    def test_safety_net_speeds_up_mutes_and_restores_without_seeking(self):
        o = self.run_yt()
        self.assertEqual((o["ad"]["muted"], o["ad"]["rate"], o["ad"]["skips"]), (True, 16, 1))
        self.assertEqual(o["ad"]["time"], 5)                  # never seeks, so it can't cut a real video short
        self.assertEqual((o["after"]["muted"], o["after"]["rate"], o["after"]["time"]), (False, 1.5, 5))

    def test_blocker_dialog_is_removed_and_video_resumed(self):
        o = self.run_yt()
        self.assertEqual(o["nag"], {"removed": "nag,backdrop", "played": 1})

    def test_only_runs_on_youtube(self):
        for host in ("example.com", "notyoutube.com", "youtube.com.evil.io"):
            code = YT_HARNESS.replace("%HOST%", host).replace("%SCRIPT%", S.YT_JS)
            r = run_js(code)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse(json.loads(r.stdout.strip().splitlines()[-1])["parsePatched"], host)
        for host in ("www.youtube.com", "m.youtube.com", "youtube.com"):
            self.assertTrue(self.run_yt(host)["parsePatched"], host)

    def test_host_helper(self):
        self.assertTrue(S.is_youtube_host("www.youtube.com") and S.is_youtube_host("YouTube.com."))
        self.assertFalse(S.is_youtube_host("youtube.com.evil.io") or S.is_youtube_host("notyoutube.com") or S.is_youtube_host(""))

    def test_syntax(self):
        SyntaxChecks().check("yt", S.YT_JS)


if __name__ == "__main__":
    unittest.main()
