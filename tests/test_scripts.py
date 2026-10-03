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


if __name__ == "__main__":
    unittest.main()
