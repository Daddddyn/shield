"""
shield_pages.py: the browser's internal pages (shield://settings, security, downloads...)

Hardening of internal pages:
  * private shield:// scheme; remote sites cannot load, link to, or fetch it
    (the handler rejects any request whose initiator is not shield:// or the browser itself)
  * every action needs a per-session secret token
  * strict Content-Security-Policy with a per-page script nonce, no remote anything
  * every dynamic string (page titles, URLs, file names) is HTML-escaped on the server,
    and inserted with textContent on the client

Design: one small design system (tokens, type scale, a single easing curve family) shared by every page,
and one SVG icon set (shield_icons.py). No emoji, no icon fonts, no remote assets.
"""
import html
import json
import secrets
import sys
import time
from urllib.parse import urlparse

from PyQt6.QtCore import QBuffer, QIODevice, QUrl, QUrlQuery
from PyQt6.QtWebEngineCore import QWebEngineUrlRequestJob, QWebEngineUrlSchemeHandler

from shield_core import (
    HOME, SEARCH_ENGINES, TRACKERS, VERSION, set_vt_key, site_of,
)
from shield_proxy import bundle_status
from shield_icons import sprite

esc = html.escape


_ON = ' style="--p:1;--c:1"'     # a switch that starts on, drawn already in place


def ic(name, size=18, cls=""):
    return f'<svg class="ic {cls}" width="{size}" height="{size}"><use href="#i-{name}"/></svg>'


# --------------------------------------------------------------------------
# Design system
# --------------------------------------------------------------------------
CSS = r"""
:root{--ease:cubic-bezier(.22,1,.36,1);--smooth:linear(0,0.009,0.032,0.067,0.109,0.155,0.205,0.256,0.307,0.358,0.407,0.454,0.499,0.542,0.582,0.619,0.654,0.686,0.716,0.743,0.768,0.791,0.811,0.83,0.848,0.863,0.877,0.89,0.902,0.912,0.921,0.93,0.937,0.944,0.95,0.956,0.961,0.965,0.969,0.972,0.975,0.978,0.981,0.983,0.985,0.986,0.988,0.989,0.991,0.992,0.993,0.993,0.994,0.995,0.995,0.996,0.996,0.997,0.997,0.998,0.998,0.998,0.998,1);--spring:linear(0,0.007,0.028,0.059,0.098,0.144,0.194,0.246,0.301,0.356,0.411,0.465,0.517,0.567,0.614,0.659,0.701,0.74,0.776,0.809,0.839,0.866,0.89,0.912,0.931,0.948,0.962,0.975,0.986,0.995,1.002,1.009,1.014,1.017,1.02,1.023,1.024,1.025,1.025,1.025,1.025,1.024,1.023,1.022,1.021,1.02,1.018,1.017,1.015,1.014,1.013,1.011,1.01,1.009,1.008,1.007,1.006,1.005,1.004,1.004,1.003,1.002,1.002,1);--r:14px;
color-scheme:dark;--bg:#111113;--side:#161618;--surface:#1c1c1f;--surface2:#27272b;--thumb:#3d3d43;--hover:rgba(255,255,255,.06);
--line:rgba(255,255,255,.085);--text:#f5f5f7;--mut:#a1a1a8;--faint:#6c6c73;--acc:#0a84ff;--acc-t:#58a8ff;
--ok:#32d74b;--okf:#30d158;--warn:#ffb340;--bad:#ff5a50;--shadow:0 1px 2px rgba(0,0,0,.4),0 18px 48px rgba(0,0,0,.45)}
[data-theme=light]{color-scheme:light;--bg:#f5f5f7;--side:#ebebf0;--surface:#fff;--surface2:#f0f0f4;--thumb:#fff;--hover:rgba(0,0,0,.05);
--line:rgba(0,0,0,.09);--text:#1d1d1f;--mut:#6e6e73;--faint:#a1a1a6;--acc:#007aff;--acc-t:#0062cc;
--ok:#1e8a39;--okf:#34c759;--warn:#a85a00;--bad:#d1281d;--shadow:0 1px 2px rgba(0,0,0,.06),0 18px 48px rgba(0,0,0,.14)}
*{box-sizing:border-box}
html{background:var(--bg);scrollbar-gutter:stable;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI Variable Text","Segoe UI",system-ui,"Helvetica Neue",sans-serif;
-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--acc-t);text-decoration:none;transition:opacity .2s}a:hover{opacity:.75}
a:focus{outline:none}a:focus-visible{outline:2px solid color-mix(in srgb,var(--acc) 70%,transparent);outline-offset:2px;border-radius:8px}
::selection{background:color-mix(in srgb,var(--acc) 38%,transparent)}
.ic{fill:none;stroke:currentColor;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round;flex:none;display:block}
.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:12px;color:var(--mut);word-break:break-all}
.shell{display:flex;min-height:100vh}
nav{width:236px;flex:none;position:sticky;top:0;height:100vh;padding:30px 12px;background:var(--side);border-right:1px solid var(--line);display:flex;flex-direction:column;gap:2px}
.brand{display:flex;align-items:center;gap:10px;padding:0 10px 24px;font-size:15px;font-weight:620;letter-spacing:-.015em}
.mk{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;color:#fff;background:linear-gradient(150deg,#58a8ff,#0a6cff);box-shadow:0 1px 0 rgba(255,255,255,.25) inset,0 4px 10px rgba(10,108,255,.35)}
nav a{display:flex;align-items:center;gap:11px;padding:8px 10px;border-radius:9px;color:var(--text);font-size:14px;transition:background .2s var(--ease),color .2s}
nav a .ic{color:var(--mut);transition:color .2s}
nav a:hover{background:var(--hover);opacity:1}
nav a.on{background:color-mix(in srgb,var(--acc) 17%,transparent);color:var(--acc-t);font-weight:560}nav a.on .ic{color:var(--acc-t)}
main{flex:1;min-width:0;max-width:840px;margin:0 auto;padding:46px 44px 140px}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes softin{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes pop{0%{opacity:0;transform:scale(.6)}60%{opacity:1;transform:scale(1.08)}100%{transform:scale(1)}}
@keyframes draw{from{stroke-dashoffset:90}to{stroke-dashoffset:0}}
@keyframes ring{0%{transform:scale(.55);opacity:.7}100%{transform:scale(2.2);opacity:0}}
@keyframes rot{to{transform:rotate(360deg)}}
@keyframes slide{0%{transform:translateX(-110%)}100%{transform:translateX(310%)}}
main>*{animation:rise .6s var(--ease) both}
h1{font-size:32px;line-height:1.1;letter-spacing:-.032em;font-weight:660;margin:0 0 8px}
.lede{color:var(--mut);margin:0 0 30px;max-width:58ch;font-size:15px;line-height:1.5}
h2{font-size:13px;font-weight:600;color:var(--mut);margin:36px 0 9px 6px}
.group{background:var(--surface);border-radius:var(--r);box-shadow:0 0 0 1px var(--line)}
.item{display:flex;align-items:center;gap:18px;padding:13px 16px;min-height:54px;position:relative}
.item+.item::before{content:"";position:absolute;top:0;left:16px;right:0;height:1px;background:var(--line)}
.grow{flex:1;min-width:0}.t{font-weight:520;font-size:14px}.d{color:var(--mut);font-size:12.5px;margin-top:2px;line-height:1.45}
.ctl{display:flex;align-items:center;gap:8px;flex:none}
.sw{--p:0;--c:0;--s:0;--off:color-mix(in srgb,var(--mut) 32%,transparent);position:relative;width:51px;height:31px;flex:none;cursor:pointer;user-select:none;-webkit-tap-highlight-color:transparent}
.sw input{position:absolute;inset:0;opacity:0;margin:0;pointer-events:none}
.sw i{position:absolute;inset:0;border-radius:99px;background:color-mix(in srgb,var(--okf) calc(var(--c)*100%),var(--off))}
.sw i::after{content:"";position:absolute;top:2px;left:2px;width:calc(27px + var(--s)*7px);height:27px;border-radius:99px;background:#fff;box-shadow:0 3px 8px rgba(0,0,0,.15),0 1px 1px rgba(0,0,0,.16),0 3px 1px rgba(0,0,0,.1);transform:translate3d(calc(var(--p)*20px - var(--s)*var(--p)*7px),0,0);will-change:transform}
.sw input:focus-visible+i{outline:2px solid color-mix(in srgb,var(--acc) 70%,transparent);outline-offset:2px}
.btn{appearance:none;border:0;font:inherit;font-weight:520;font-size:13px;color:var(--text);background:var(--surface2);padding:7px 14px;border-radius:9px;cursor:pointer;
display:inline-flex;align-items:center;gap:7px;line-height:1.25;white-space:nowrap;transition:background .2s var(--ease),transform .5s var(--spring),opacity .2s,color .2s}
.btn:hover{background:color-mix(in srgb,var(--surface2) 82%,var(--text));opacity:1}.btn:active{transform:scale(.955);transition-duration:.2s,.08s,.2s,.2s}
.btn.pri{background:var(--acc);color:#fff}.btn.pri:hover{background:color-mix(in srgb,var(--acc) 86%,#fff)}
.btn.dng{color:var(--bad)}.btn.dng.fill{background:var(--bad);color:#fff}
.btn.ghost{background:transparent}.btn.ghost:hover{background:var(--hover)}
.btn.icon{padding:7px;border-radius:9px}.btn.lg{padding:10px 20px;font-size:14px;border-radius:11px}
.btn[disabled]{opacity:.4;pointer-events:none}
.btn:focus-visible{outline:2px solid color-mix(in srgb,var(--acc) 70%,transparent);outline-offset:2px}
.inp{font:inherit;color:var(--text);background:var(--surface2);border:0;border-radius:9px;padding:8px 12px;outline:0;box-shadow:inset 0 0 0 2px transparent;transition:box-shadow .25s var(--ease)}
.inp:focus{box-shadow:inset 0 0 0 2px color-mix(in srgb,var(--acc) 70%,transparent)}
select.inp{appearance:none;padding-right:32px;cursor:pointer;background-repeat:no-repeat;background-position:right 11px center;
background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238e8e93' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9.5l6 6 6-6'/%3E%3C/svg%3E")}
textarea.inp{width:100%;min-height:100px;font:12.5px/1.6 ui-monospace,Menlo,Consolas,monospace;resize:vertical;padding:10px 12px}
.seg{position:relative;display:inline-flex;background:var(--surface2);border-radius:10px;padding:2px}
.seg button{position:relative;z-index:1;appearance:none;border:0;background:none;font:inherit;font-size:13px;font-weight:520;color:var(--mut);padding:5px 14px;border-radius:8px;cursor:pointer;transition:color .22s var(--ease)}
.seg button.on{color:var(--text)}
.seg .thumb{position:absolute;top:2px;bottom:2px;left:0;border-radius:8px;background:var(--thumb);box-shadow:0 1px 3px rgba(0,0,0,.22),0 0 0 .5px var(--line);will-change:transform}
.chip{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:560;padding:2px 9px;border-radius:99px;background:var(--surface2);color:var(--mut);line-height:1.5}
.chip.ok{color:var(--ok);background:color-mix(in srgb,var(--okf) 15%,transparent)}.chip.warn{color:var(--warn);background:color-mix(in srgb,var(--warn) 16%,transparent)}
.chip.bad{color:var(--bad);background:color-mix(in srgb,var(--bad) 15%,transparent)}.chip.acc{color:var(--acc-t);background:color-mix(in srgb,var(--acc) 16%,transparent)}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.stat{background:var(--surface);border-radius:var(--r);box-shadow:0 0 0 1px var(--line);padding:16px 18px}
.stat b{display:block;font-size:30px;font-weight:620;letter-spacing:-.03em;font-variant-numeric:tabular-nums;line-height:1.15}.stat span{color:var(--mut);font-size:12.5px}
.hero{display:flex;align-items:center;gap:20px;padding:22px 24px;margin-bottom:22px;border-radius:18px;background:linear-gradient(135deg,color-mix(in srgb,var(--okf) 17%,var(--surface)),var(--surface) 75%);box-shadow:0 0 0 1px var(--line)}
.hero .orb{width:58px;height:58px;border-radius:50%;display:grid;place-items:center;color:var(--ok);background:color-mix(in srgb,var(--okf) 20%,transparent);flex:none}
.hero h3{margin:0;font-size:20px;font-weight:620;letter-spacing:-.02em}.hero p{margin:3px 0 0;color:var(--mut)}
.row-ic{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;flex:none;color:var(--mut);background:var(--surface2)}
.fav{width:30px;height:30px;border-radius:8px;flex:none;display:grid;place-items:center;background:var(--surface2);color:var(--mut);font-weight:620;font-size:13px;overflow:hidden}
.fav img{width:18px;height:18px;border-radius:4px}
.hide{opacity:0;transition:opacity .2s}.item:hover .hide,.item:focus-within .hide{opacity:1}
.empty{padding:34px 16px;text-align:center;color:var(--mut)}
.find{display:flex;align-items:center;gap:10px;background:var(--surface);box-shadow:0 0 0 1px var(--line);border-radius:12px;padding:0 6px 0 14px;margin-bottom:6px;color:var(--mut)}
.find input{flex:1;background:none;border:0;outline:0;color:var(--text);font:inherit;padding:11px 0}
.col{display:grid;grid-template-rows:1fr;transition:grid-template-rows .45s var(--ease),opacity .45s var(--ease)}
.col>.in{overflow:hidden;min-height:0}.col.gone{grid-template-rows:0fr;opacity:0}
.gap{margin-bottom:12px;transition:margin .45s var(--ease)}.gap.gone{margin-bottom:0}
/* downloads */
.dl{background:var(--surface);border-radius:var(--r);box-shadow:0 0 0 1px var(--line)}
.dl-h{display:flex;align-items:center;gap:14px;padding:14px 16px}
.dl .fi{width:42px;height:42px;border-radius:11px;display:grid;place-items:center;flex:none;color:var(--acc-t);background:color-mix(in srgb,var(--acc) 14%,transparent)}
.dl .nm{font-weight:560;font-size:14.5px;display:flex;align-items:center;gap:8px;min-width:0}.dl .nm span.n{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dl .mt{color:var(--mut);font-size:12.5px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.acts{display:flex;gap:6px;flex:none;align-items:center}
.bar{height:4px;border-radius:99px;background:var(--surface2);overflow:hidden;margin:0 16px 14px}
.bar i{display:block;height:100%;width:0;border-radius:99px;background:var(--acc);transition:width .7s linear}
.bar.ind i{width:34%;animation:slide 1.3s var(--ease) infinite}
.verdict{--tone:var(--mut);display:flex;gap:14px;align-items:flex-start;margin:0 12px 12px;padding:14px 16px;border-radius:12px;background:color-mix(in srgb,var(--tone) 10%,transparent);animation:fade .5s var(--ease)}
.verdict .bd{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;color:var(--tone);background:color-mix(in srgb,var(--tone) 18%,transparent);flex:none}
.verdict .bd .ic{animation:pop .55s var(--spring) both,draw .8s var(--ease) both}
.verdict h4{margin:0;font-size:14.5px;font-weight:620;letter-spacing:-.01em;color:var(--tone)}.verdict p{margin:2px 0 0;color:var(--text);opacity:.82;font-size:13px;line-height:1.5}
.tone-ok{--tone:var(--ok)}.tone-warn{--tone:var(--warn)}.tone-bad{--tone:var(--bad)}.tone-info{--tone:var(--acc-t)}
.ring{width:18px;height:18px;border-radius:50%;border:2.2px solid color-mix(in srgb,var(--acc) 22%,transparent);border-top-color:var(--acc);animation:rot .75s linear infinite}
.more{display:grid;grid-template-rows:0fr;transition:grid-template-rows .45s var(--ease)}.more.open{grid-template-rows:1fr}
.more>div{overflow:hidden;min-height:0}
.pane{border-top:1px solid var(--line);padding:6px 16px 14px}
.pane h5{margin:14px 0 6px;font-size:12px;font-weight:600;color:var(--mut)}
.fr{display:flex;gap:11px;padding:6px 0;align-items:flex-start;font-size:13px}.fr .ic{margin-top:2px}.fr small{display:block;color:var(--mut);font-size:12.5px;line-height:1.45}
.fr.good .ic{color:var(--ok)}.fr.warn .ic{color:var(--warn)}.fr.bad .ic{color:var(--bad)}.fr.info .ic{color:var(--faint)}
.vt{display:flex;align-items:center;gap:14px;padding:12px 14px;border-radius:12px;background:var(--surface2)}
.vt .big{font-size:26px;font-weight:620;letter-spacing:-.03em;font-variant-numeric:tabular-nums;line-height:1}.vt .big small{font-size:13px;color:var(--mut);font-weight:500;letter-spacing:0}
.tog{transition:transform .4s var(--spring)}.tog.up{transform:rotate(180deg)}
/* sheet + toast */
.sheet-bg{position:fixed;inset:0;display:grid;place-items:center;padding:24px;background:rgba(0,0,0,.42);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);opacity:0;transition:opacity .3s var(--ease);z-index:50}
.sheet-bg.on{opacity:1}
.sheet{will-change:transform,opacity;width:min(420px,100%);background:var(--surface);border-radius:20px;padding:26px 24px 20px;box-shadow:var(--shadow),0 0 0 1px var(--line);text-align:center;transform:translateY(18px) scale(.95);opacity:0;transition:transform .5s var(--spring),opacity .3s var(--ease)}
.sheet-bg.on .sheet{transform:none;opacity:1}
.sheet .bd{width:52px;height:52px;border-radius:50%;margin:0 auto 14px;display:grid;place-items:center;color:var(--tone,var(--acc-t));background:color-mix(in srgb,var(--tone,var(--acc)) 16%,transparent)}
.sheet h3{margin:0 0 6px;font-size:18px;font-weight:640;letter-spacing:-.02em}.sheet p{margin:0 0 4px;color:var(--mut);line-height:1.5;font-size:13.5px}
.sheet .inp{width:100%;margin-top:14px;text-align:left}.sheet .btns{display:flex;flex-direction:column;gap:8px;margin-top:20px}.sheet .btn{justify-content:center;padding:11px 16px;font-size:14px;border-radius:11px}
#toast{position:fixed;left:50%;bottom:28px;transform:translate(-50%,16px) scale(.96);padding:10px 18px;border-radius:99px;font-size:13px;font-weight:520;background:color-mix(in srgb,var(--surface) 82%,transparent);-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px);
box-shadow:var(--shadow),0 0 0 1px var(--line);opacity:0;pointer-events:none;transition:opacity .3s var(--ease),transform .5s var(--spring);z-index:60}
#toast.show{opacity:1;transform:translate(-50%,0) scale(1)}
/* passwords, forms */
.meter{display:flex;gap:4px;margin-top:8px}.meter i{flex:1;height:4px;border-radius:99px;background:var(--surface2);transition:background .3s var(--ease)}
.meter[data-s="0"] i:nth-child(-n+1),.meter[data-s="1"] i:nth-child(-n+2){background:var(--bad)}
.meter[data-s="2"] i:nth-child(-n+3){background:var(--warn)}
.meter[data-s="3"] i:nth-child(-n+4),.meter[data-s="4"] i:nth-child(-n+5){background:var(--okf)}
.fld{display:flex;flex-direction:column;gap:6px;text-align:left;margin-top:13px}.fld>label{font-size:12px;color:var(--mut);font-weight:560}.fld .inp{width:100%}
.fld .row{display:flex;gap:6px}.fld .row .inp{flex:1;min-width:0}
.err{color:var(--bad);font-size:12.5px;min-height:18px;margin-top:8px;text-align:left}
.sheet.wide{width:min(460px,100%)}.sheet .btns.row{flex-direction:row}.sheet .btns.row .btn{flex:1}
.actions{display:flex;gap:6px;align-items:center;flex:none}
.card{background:var(--surface);border-radius:var(--r);box-shadow:0 0 0 1px var(--line);padding:26px 24px;max-width:460px;margin:8px auto 0;text-align:center}
.card .bd{width:56px;height:56px;border-radius:50%;margin:0 auto 14px;display:grid;place-items:center;color:var(--acc-t);background:color-mix(in srgb,var(--acc) 16%,transparent)}
.card h3{margin:0 0 6px;font-size:19px;font-weight:640;letter-spacing:-.02em}.card p{margin:0;color:var(--mut);line-height:1.5;font-size:13.5px}
.card .btn.lg{width:100%;justify-content:center;margin-top:18px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 4px}
.pwv{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:12.5px;color:var(--text);background:var(--surface2);padding:2px 8px;border-radius:7px;word-break:break-all}
.sub{display:block;color:var(--mut);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* new tab + warning */
.shell>.center{flex:1;min-width:0}
.center{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 24px 90px;text-align:center;
background:radial-gradient(900px 480px at 50% 24%,color-mix(in srgb,var(--acc) 13%,transparent),transparent 70%)}
.center>*{animation:rise .9s var(--ease) both}
.logo{display:flex;align-items:center;gap:14px;font-size:44px;font-weight:660;letter-spacing:-.04em;margin-bottom:30px}
.logo .mk{width:54px;height:54px;border-radius:15px}
.search{display:flex;align-items:center;gap:12px;width:min(600px,92vw);padding:0 22px;height:54px;border-radius:99px;background:var(--surface);color:var(--mut);
box-shadow:0 0 0 1px var(--line),0 6px 22px rgba(0,0,0,.14);transition:box-shadow .35s var(--ease),transform .5s var(--spring)}
.search:focus-within{box-shadow:0 0 0 2px color-mix(in srgb,var(--acc) 70%,transparent),0 12px 34px rgba(0,0,0,.2);transform:scale(1.012)}
.search input{flex:1;background:none;border:0;outline:0;color:var(--text);font:inherit;font-size:16.5px;min-width:0}
.tiles{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:40px;max-width:640px}
.tile{width:104px;padding:12px 6px 10px;border-radius:14px;color:var(--text);font-size:12.5px;display:flex;flex-direction:column;align-items:center;gap:9px;transition:background .25s var(--ease),transform .4s var(--spring)}
.tile:hover{background:var(--hover);opacity:1;transform:translateY(-2px)}.tile:active{transform:scale(.95)}
.tile .fav{width:56px;height:56px;border-radius:15px;font-size:20px;box-shadow:0 0 0 1px var(--line);background:var(--surface)}.tile .fav img{width:30px;height:30px;border-radius:7px}
.tile span.l{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.foot{position:fixed;left:0;right:0;bottom:22px;text-align:center;color:var(--faint);font-size:12.5px}.foot a{color:var(--mut)}
.warnbox{max-width:480px;text-align:center;display:flex;flex-direction:column;align-items:center}
.warnbox .bd{width:68px;height:68px;border-radius:50%;display:grid;place-items:center;color:var(--bad);background:color-mix(in srgb,var(--bad) 15%,transparent);margin-bottom:22px}
.warnbox .bd .ic{animation:pop .7s var(--spring) .15s both,draw .9s var(--ease) .15s both}
.warnbox h1{font-size:28px}.warnbox p{color:var(--mut);line-height:1.55;margin:0 0 14px}.warnbox p b{color:var(--text);font-weight:600}
.warnbox .mono{background:var(--surface);padding:9px 14px;border-radius:10px;max-width:100%;margin-bottom:26px;box-shadow:0 0 0 1px var(--line)}
@media(max-width:760px){nav{display:none}main{padding:28px 18px 120px}}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
"""
CSS += """.verdict .bd,.sheet .bd,.warnbox .bd{position:relative}
.sheet .bd .ic,.verdict .bd .ic,.warnbox .bd .ic{stroke-dasharray:90}
.sheet-bg.on .bd .ic{animation:draw .75s var(--ease) .12s both}
.verdict .bd::after,.warnbox .bd::after,.sheet-bg.on .bd::after{content:"";position:absolute;inset:0;border-radius:50%;border:2px solid currentColor;opacity:0;animation:ring 1.1s var(--ease) .1s forwards;pointer-events:none}
"""
CSS += "".join(f"main>*:nth-child({i}){{animation-delay:{(i - 1) * 32}ms}}" for i in range(2, 16))
# Arriving from another internal page: a short fade, no staggered intro, so switching sections feels instant.
CSS += ".soft main>*{animation:softin .2s var(--ease) both!important;animation-delay:0ms!important}\n"

BASE_JS = r"""
const T="__T__",NS="http://www.w3.org/2000/svg",$=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const api=(p,q={})=>fetch("/api/"+p+"?"+new URLSearchParams({...q,t:T})).then(r=>r.json()).catch(()=>({ok:false,err:"Couldn't reach Shield"}));
const ic=(n,s=18,c="")=>{const e=document.createElementNS(NS,"svg");e.setAttribute("class","ic "+c);e.setAttribute("width",s);e.setAttribute("height",s);const u=document.createElementNS(NS,"use");u.setAttribute("href","#i-"+n);e.append(u);return e};
const h=(t,a={},...k)=>{const e=document.createElement(t);for(const x in a){const v=a[x];if(x==="class")e.className=v;else if(x.startsWith("on"))e.addEventListener(x.slice(2),v);else if(v!==false&&v!=null)e.setAttribute(x,v===true?"":v)}e.append(...k.flat(9).filter(c=>c!=null&&c!==false));return e};
let _tt;const toast=m=>{const e=$("#toast");e.textContent=m;e.classList.add("show");clearTimeout(_tt);_tt=setTimeout(()=>e.classList.remove("show"),2400)};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function sheet({icon="info",tone="",title,body,field,actions}){return new Promise(res=>{
 const inp=field?h("input",{class:"inp",type:field.type||"text",placeholder:field.placeholder||"",autocomplete:"off",spellcheck:"false"}):null;
 const close=async v=>{bg.classList.remove("on");document.removeEventListener("keydown",key,true);await sleep(320);bg.remove();res(v)};
 const key=e=>{if(e.key==="Escape"){e.stopPropagation();close(null)}else if(e.key==="Enter"&&inp){e.preventDefault();close({value:inp.value})}};
 const btns=actions.map(a=>h("button",{class:"btn "+(a.kind||""),onclick:()=>close(inp?{value:a.value===null?null:inp.value,action:a.value}:a.value)},a.label));
 const bg=h("div",{class:"sheet-bg",style:tone?`--tone:var(--${tone})`:"",onmousedown:e=>{if(e.target===bg)close(null)}},
  h("div",{class:"sheet",role:"dialog","aria-modal":"true"},h("div",{class:"bd"},ic(icon,26)),h("h3",{},title),h("p",{},body),inp,h("div",{class:"btns"},btns)));
 document.body.append(bg);document.addEventListener("keydown",key,true);bg.offsetWidth;bg.classList.add("on");if(inp)setTimeout(()=>inp.focus(),120);
})}
const RM=matchMedia("(prefers-reduced-motion:reduce)").matches;
const SPR=(x,v,t,w,z,dt)=>{const d=x-t;if(z>=.999){const e=Math.exp(-w*dt),j=v+w*d;return[t+(d+j*dt)*e,(v-j*w*dt)*e]}
 const wd=w*Math.sqrt(1-z*z),e=Math.exp(-z*w*dt),c=Math.cos(wd*dt),s=Math.sin(wd*dt),b=(v+z*w*d)/wd;return[t+e*(d*c+b*s),e*(v*c-((z*w*v+w*w*d)/wd)*s)]};
function springer(step){let raf=0,last=0;const f=t=>{const dt=Math.min(.05,Math.max(.001,(t-last)/1000));last=t;raf=step(dt)?requestAnimationFrame(f):0};
 return()=>{if(!raf){last=performance.now();raf=requestAnimationFrame(f)}}}
function sw(el){const inp=$("input",el);if(!inp||el._sw)return;el._sw=1;
 const dsc=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"checked"),want=()=>dsc.get.call(inp)?1:0;
 let P=want(),PV=0,S=0,SV=0,press=false,drag=null;
 const paint=()=>{el.style.setProperty("--p",P.toFixed(4));el.style.setProperty("--c",Math.min(1,Math.max(0,P)).toFixed(3));el.style.setProperty("--s",S.toFixed(4))};
 const go=springer(dt=>{const dr=drag&&drag.moved,tp=dr?drag.p:want(),ts=press?1:0;
  [P,PV]=SPR(P,PV,tp,dr?70:18,dr?1:.78,dt);[S,SV]=SPR(S,SV,ts,34,1,dt);
  const rest=Math.abs(P-tp)<.0008&&Math.abs(PV)<.01&&Math.abs(S-ts)<.001&&Math.abs(SV)<.01;if(rest){P=tp;S=ts;PV=SV=0}paint();return!rest});
 const kick=()=>{if(RM){P=want();S=0;PV=SV=0;paint()}else go()};
 const set=v=>{if(!!want()===v)return;dsc.set.call(inp,v);inp.dispatchEvent(new Event("change",{bubbles:true}));kick()};
 Object.defineProperty(inp,"checked",{get(){return dsc.get.call(inp)},set(v){dsc.set.call(inp,v);kick()},configurable:true});
 inp.addEventListener("change",kick);
 el.addEventListener("click",e=>{if(e.target!==inp)e.preventDefault()});
 el.addEventListener("pointerdown",e=>{if(e.button||inp.disabled)return;try{el.setPointerCapture(e.pointerId)}catch(x){}press=true;drag={x0:e.clientX,base:want(),moved:false,p:want()};kick()});
 el.addEventListener("pointermove",e=>{if(!drag)return;const dx=e.clientX-drag.x0;if(!drag.moved&&Math.abs(dx)>3)drag.moved=true;if(drag.moved){drag.p=Math.min(1,Math.max(0,drag.base+dx/20));kick()}});
 const end=ok=>{if(!drag)return;const d=drag;drag=null;press=false;if(ok){if(d.moved)set(d.p>.5);else set(!want())}kick()};
 el.addEventListener("pointerup",()=>end(true));el.addEventListener("pointercancel",()=>end(false));paint()}
$$(".sw").forEach(sw);new MutationObserver(()=>$$(".sw").forEach(sw)).observe(document.body,{childList:true,subtree:true});
function seg(el,onpick){const th=h("i",{class:"thumb"});el.append(th);const bs=$$("button",el);let X=0,XV=0,W=0,WV=0,tx=0,tw=0,ready=false;
 const cur=()=>bs.find(b=>b.classList.contains("on"))||bs[0];
 const paint=()=>{th.style.width=W.toFixed(2)+"px";th.style.transform="translate3d("+X.toFixed(2)+"px,0,0)"};
 const go=springer(dt=>{[X,XV]=SPR(X,XV,tx,22,.82,dt);[W,WV]=SPR(W,WV,tw,22,.82,dt);
  const rest=Math.abs(X-tx)<.03&&Math.abs(W-tw)<.03&&Math.abs(XV)<.5&&Math.abs(WV)<.5;if(rest){X=tx;W=tw;XV=WV=0}paint();return!rest});
 const put=(b,anim)=>{tx=b.offsetLeft;tw=b.offsetWidth;if(!anim||!ready||RM){X=tx;W=tw;XV=WV=0;paint();ready=true}else go()};
 requestAnimationFrame(()=>put(cur(),false));if(document.fonts)document.fonts.ready.then(()=>put(cur(),false));
 bs.forEach(b=>b.addEventListener("click",()=>{if(b===cur())return;bs.forEach(x=>x.classList.toggle("on",x===b));put(b,true);onpick&&onpick(b.dataset.v)}))}
function countUp(el,to){const from=+el.dataset.v||0;el.dataset.v=to;if(from===to){el.textContent=to.toLocaleString();return}
 const t0=performance.now(),d=Math.min(900,300+Math.abs(to-from)*12);const f=t=>{const p=Math.min(1,(t-t0)/d),e=1-Math.pow(1-p,3);el.textContent=Math.round(from+(to-from)*e).toLocaleString();if(p<1)requestAnimationFrame(f)};requestAnimationFrame(f)}
const fmtSize=n=>{n=+n||0;const u=["B","KB","MB","GB"];let i=0;while(n>=1024&&i<3){n/=1024;i++}return (i?n.toFixed(1):n.toFixed(0))+" "+u[i]};
const ago=ts=>{const s=Date.now()/1000-ts;if(s<45)return"Just now";if(s<3600)return Math.round(s/60)+" min ago";const d=new Date(ts*1000),n=new Date();
 const hm=d.toLocaleTimeString([],{hour:"numeric",minute:"2-digit"});if(d.toDateString()===n.toDateString())return"Today, "+hm;const y=new Date(n-864e5);if(d.toDateString()===y.toDateString())return"Yesterday, "+hm;return d.toLocaleDateString([],{month:"short",day:"numeric"})+", "+hm};
"""

NAV = [("settings", "Settings", "sliders"), ("security", "Security center", "shield-check"), ("passwords", "Passwords", "key"),
       ("downloads", "Downloads", "download"), ("history", "History", "clock"), ("bookmarks", "Bookmarks", "bookmark")]


class Ctx:
    def __init__(self, cfg, events, store, guard):
        self.cfg, self.events, self.store, self.guard = cfg, events, store, guard
        self.token = secrets.token_urlsafe(24)
        self.app = None        # set to the Browser window
        self.engine = {"chromium": "unknown", "flags": ""}
        self.soft_to = None    # (page, time) set when the user clicks from one internal page to another


def shell(ctx, title, body, script="", nav=None):
    nonce = secrets.token_urlsafe(12)
    side = ""
    if nav is not None:
        links = "".join(f'<a class="{"on" if h == nav else ""}" href="shield://{h}">{ic(i, 18)}{lbl}</a>' for h, lbl, i in NAV)
        side = f'<nav><div class="brand"><span class="mk">{ic("shield-check", 17)}</span>Shield</div>{links}</nav>'
    csp = (f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; "
           "img-src data:; connect-src shield:; form-action https:; base-uri 'none'")
    theme = ctx.app.resolved_theme() if ctx.app else "dark"
    soft = False
    if nav is not None and ctx.soft_to and ctx.soft_to[0] == nav and time.monotonic() - ctx.soft_to[1] < 3.0:
        soft = True
    ctx.soft_to = None
    js = BASE_JS.replace("__T__", ctx.token) + script
    main = f"<main>{body}</main>" if nav is not None else body
    return (f'<!doctype html><html data-theme="{esc(theme)}"{" class=soft" if soft else ""}><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="{csp}"><title>{esc(title)}</title>'
            f'<style>{CSS}</style></head><body>{sprite()}<div class="shell">{side}{main}</div>'
            f'<div id="toast"></div><script nonce="{nonce}">{js}</script></body></html>')


def fmt_size(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def fmt_time(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def ago_text(ts):
    if not ts:
        return "never"
    d = max(0, time.time() - ts)
    if d < 90:
        return "just now"
    if d < 5400:
        return f"{round(d / 60)} min ago"
    if d < 129600:
        return f"{round(d / 3600)} h ago"
    return f"{round(d / 86400)} days ago"


def day_label(ts):
    d = time.strftime("%Y-%m-%d", time.localtime(ts))
    if d == time.strftime("%Y-%m-%d"):
        return "Today"
    if d == time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400)):
        return "Yesterday"
    return time.strftime("%A, %B %d", time.localtime(ts)).replace(" 0", " ")


def fav_html(ctx, url, cls="fav"):
    host = urlparse(url).hostname or ""
    uri = ctx.store.favicon_uri(host)
    inner = f'<img alt="" src="{uri}">' if uri else esc((host.replace("www.", "")[:1] or "?").upper())
    return f'<span class="{cls}">{inner}</span>'


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
def _item(label, desc="", control=""):
    d = f'<div class="d">{desc}</div>' if desc else ""
    return f'<div class="item"><div class="grow"><div class="t">{label}</div>{d}</div><div class="ctl">{control}</div></div>'


def toggle(cfg, key, label, desc):
    on = "checked" if cfg[key] else ""
    return _item(label, desc, f'<label class="sw"{_ON if on else ""}><input type="checkbox" data-k="{key}" {on}><i></i></label>')


def segmented(cfg, key, label, desc, options):
    btns = "".join(f'<button data-v="{esc(str(v))}" class="{"on" if cfg[key] == v else ""}">{esc(n)}</button>' for v, n in options)
    return _item(label, desc, f'<div class="seg" data-k="{key}">{btns}</div>')


def select(cfg, key, label, desc, options):
    opts = "".join(f'<option value="{esc(str(v))}" {"selected" if cfg[key] == v else ""}>{esc(n)}</option>' for v, n in options)
    return _item(label, desc, f'<select class="inp" data-k="{key}">{opts}</select>')


def _list_line(it):
    if not it["have"]:
        return "Not downloaded yet" if it["on"] else "Off"
    return f"{fmt_size(it['size'])} \u00b7 updated {ago_text(it['ts'])}"


def _summary_line(summ):
    if not summ.get("ready"):
        return "Protection lists are still loading."
    return (f"{summ['network']:,} blocking rules, {summ['cosmetic']:,} page-cleanup rules and "
            f"{summ['threats']:,} known-bad addresses are active.")


def _app_updates_configured():
    try:
        import shield_update
        return shield_update.configured()
    except Exception:
        return False


def page_settings(ctx, q):
    c = ctx.cfg
    engines = [(k, v[0]) for k, v in SEARCH_ENGINES.items()]
    general = (
        segmented(c, "theme", "Appearance", "Applies to the browser and its internal pages.",
                  [("dark", "Dark"), ("light", "Light"), ("system", "Auto")])
        + _item("Home page", "Opened by the Home button and on startup.",
                f'<input class="inp" type="text" data-k="homepage" value="{esc(c["homepage"])}" size="26" spellcheck="false">')
        + select(c, "search_engine", "Search engine", "Used for the address bar and the new tab page.", engines)
        + segmented(c, "history_days", "Keep browsing history", "Stored only on this computer and pruned automatically.",
                    [(0, "Off"), (7, "7 days"), (30, "30 days"), (90, "90 days")])
        + segmented(c, "startup", "When Shield opens", "Continue where you left off reopens the pages from your last session. Nothing is saved unless you choose this.",
                    [("home", "Home page"), ("restore", "Where I left off")])
        + toggle(c, "persistent_sessions", "Stay signed in between sessions",
                 "Off means cookies and site data are wiped on exit, which is the most private. Needs a restart.")
        + toggle(c, "clear_on_exit", "Clear cookies and cache when Shield closes",
                 "Only matters if you stay signed in between sessions. Sites will ask you to sign in again.")
        + toggle(c, "sound_effects", "Sound effects",
                 f"Plays sounds you choose for clicks and for tabs opening. Put click.wav, open.wav and scroll.wav in "
                 f"<span class=\"mono\">{esc(str(HOME / 'sounds'))}</span> (.wav plays fastest; .mp3 and .ogg work too). Nothing is built in.")
        + toggle(c, "sound_scroll", "Scroll sound", "Plays your scroll sound in small ticks while you scroll a page. Needs sound effects on.")
        + segmented(c, "sound_volume", "Sound volume", "How loud the interface sounds are.", [(30, "Soft"), (60, "Medium"), (100, "Loud")])
        + toggle(c, "hardened_mode", "Hardened mode (no JIT)",
                 "Runs JavaScript without the JIT compiler, which most browser exploits rely on. Heavy pages, games and web apps run slower, and WebAssembly stops working. Needs a restart.")
    )
    app0 = ctx.app
    summ = app0.protection_summary() if app0 else {"network": 0, "cosmetic": 0, "threats": 0, "ready": False}
    privacy = (
        toggle(c, "https_only", "HTTPS-only mode", "Upgrades every http:// request. If a site can't do HTTPS you get a warning instead of a silent downgrade.")
        + toggle(c, "block_trackers", "Block ads and trackers",
                 f"Uses the protection lists below ({summ['network']:,} rules loaded) plus {len(TRACKERS):,} built-in tracking domains. Turn it off for one site from the lock icon.")
        + toggle(c, "block_site_ads", "Block ads on websites",
                 "Blocks banner, video and pop-up ads on every site. Turn it off if you want websites to show their ads: "
                 "trackers stay blocked either way.")
        + toggle(c, "block_youtube_ads", "Block YouTube ads",
                 "Removes video and page ads on youtube.com by changing the data YouTube's player is given. YouTube changes its "
                 "player often, so now and then an ad may get through until Shield is updated. Applies to the next YouTube page you open.")
        + toggle(c, "cosmetic_filtering", "Hide empty ad spaces", "Removes the blank boxes and banners that blocked ads leave behind.")
        + toggle(c, "block_harmful", "Warn about harmful sites", "Warns before known phishing, malware and scam pages open. Matching happens on this computer; the addresses you visit are never sent anywhere.")
        + toggle(c, "clean_links", "Clean tracking out of links", "Removes tracking parameters like utm_ and fbclid when you click a link, and skips redirect pages that only exist to count clicks.")
        + toggle(c, "block_third_party_cookies", "Block third-party cookies", "Stops cross-site tracking cookies. May break some embedded logins.")
        + toggle(c, "block_local_network", "Local network shield", "Public websites can't send requests to localhost or your LAN: router, printers, dev servers.")
        + toggle(c, "fingerprint_protection", "Fingerprint protection", "Normalizes language and hardware hints and adds tiny noise to canvas, audio and WebGL reads. The noise differs for every site, so sites can't compare notes. Applies to new pages.")
        + segmented(c, "fingerprint_level", "Fingerprint strength", "Strict also hides your graphics card name and rounds your screen size. A few sites that check them may misbehave.",
                    [("standard", "Standard"), ("strict", "Strict")])
        + toggle(c, "send_gpc", "Global Privacy Control", "Tells sites you opt out of tracking and data sale.")
        + toggle(c, "navigation_guard", "Navigation guard", "Warns before opening lookalike domains, look-alike international characters and your blocked sites.")
    )
    # protection lists
    list_rows = ""
    for it in (app0.list_status() if app0 else {"lists": []})["lists"]:
        chk = "checked" if it["on"] else ""
        list_rows += _item(esc(it["name"]), f'{esc(it["desc"])}<br><span data-lst="{esc(it["id"])}">{esc(_list_line(it))}</span>',
                           f'<label class="sw"{_ON if chk else ""}><input type="checkbox" data-list="{esc(it["id"])}" {chk}><i></i></label>')
    lists = (list_rows
             + toggle(c, "auto_update_lists", "Keep lists up to date", "Fetches the lists in the background every few days over HTTPS. The requests carry no cookies, no account and no history.")
             + _item("Update now", f'<span id="lstsum">{esc(_summary_line(summ))}</span>', '<button class="btn pri" id="lstupd">Update lists</button>'))
    # passwords
    pw = (_item("Password vault", "Logins are encrypted on this computer with your master password.", '<a class="btn" href="shield://passwords">Open</a>')
          + toggle(c, "vault_autofill", "Offer to fill logins", "Adds a key button to the toolbar. Logins only fill when you pick one, only on the exact site they were saved for, and only over HTTPS.")
          + toggle(c, "vault_offer_save", "Offer to save logins", "Asks after you sign in. Never saves without asking.")
          + segmented(c, "vault_autolock", "Lock the vault after", "Locks again after this long without using it.",
                      [(5, "5 min"), (15, "15 min"), (60, "1 hour"), (0, "Never")]))
    # updates
    upd = (toggle(c, "check_updates", "Check for updates", "Looks once a day for a newer web engine, and for a newer Shield if this build has an update address. Sends nothing about you.")
           + _item("Web engine", '<span id="engline">Checking</span>', '<button class="btn" id="updchk">Check now</button>'))
    if _app_updates_configured():
        upd += _item("Shield", '<span id="appline">Checking</span>', '<span class="ctl" id="appctl"></span>')
    perms = segmented(c, "permissions", "Camera, microphone, location", "Notifications are always denied. Allowed permissions last only for the current session.",
                      [("deny", "Always deny"), ("ask", "Ask me")])
    dl = (segmented(c, "risky_downloads", "Disguised downloads", "Files with a double extension, hidden characters or a name that doesn't match what the server sent.",
                    [("ask", "Warn me"), ("block", "Block")])
          + _item("Download gate", "Every download needs your approval, waits in quarantine, is signature-checked and scanned, and is released only when you say so.",
                  '<span class="chip ok">Always on</span>'))
    # scanners
    scan_rows = ""
    app = ctx.app
    state = app.engine_state() if app else []
    for e in state:
        key = e["key"]
        right = ""
        if key in ("yara", "clamav") and (key == "yara" or e.get("installed")):
            label = "Update" if e["available"] else ("Download rules" if key == "yara" else "Download signatures")
            right += f'<button class="btn" data-update="{key}">{label}</button>'
        if key == "clamav" and not e.get("installed"):
            right += '<a class="btn" target="_blank" href="https://www.clamav.net/downloads">Get ClamAV</a>'
        if e["available"] or key != "defender":
            chk = "checked" if c.get(f"scan_{key}", True) else ""
            right += f'<label class="sw"{_ON if chk else ""}><input type="checkbox" data-k="scan_{key}" {chk}><i></i></label>'
        scan_rows += _item(esc(e["name"]), f'<span data-eng="{key}">{esc(e["detail"])}</span>', right)
    has_key = bool(app and app.has_vt_key())
    if has_key:
        keyctl = '<span class="chip ok">Key saved</span><button class="btn" id="vtchange">Change</button><button class="btn dng" id="vtremove">Remove</button>'
    else:
        keyctl = '<button class="btn pri" id="vtchange">Add key</button>'
    vt = (_item("VirusTotal API key", 'Needed to look files up and upload them for scanning. A free key from <a target="_blank" href="https://www.virustotal.com/gui/join-us">virustotal.com</a> is enough. It stays on this computer.',
                f'<span id="vtkeyctl" class="ctl">{keyctl}</span>')
          + toggle(c, "vt_auto_lookup", "Look up new downloads automatically", "Sends only the file's SHA-256 fingerprint, never the file.")
          + toggle(c, "vt_confirm_upload", "Ask before uploading a file", "Uploaded files can be seen by VirusTotal and the security companies it works with. Leave this on for anything private."))
    bs = bundle_status()
    if not bs["tor"]:
        comp = "The private connection component is not part of this copy of Shield, so the globe button is switched off."
    else:
        have = [n for n, k in (("obfs4", "obfs4"), ("Snowflake", "snowflake")) if bs[k]]
        comp = ("Bridge support in this copy of Shield: " + (" and ".join(have) if have else "none, only direct Tor") + ".")
    proxy = (
        toggle(c, "proxy_on_start", "Private connection on at startup",
               "Shield has a private connection built in (the globe button in the toolbar). It sends your browsing through Tor, so your network and internet provider can see that you use Tor but not which sites you visit. Pages load slower. Turn this on to start every session with it already running.")
        + segmented(c, "proxy_bridge_mode", "If your network blocks Tor",
                    "Work, school and some national networks block Tor. Automatic tries a normal connection first, then obfs4 and Snowflake bridges, which disguise Tor traffic, then your own bridges if you added any. " + esc(comp),
                    [("auto", "Automatic"), ("off", "No bridges"), ("obfs4", "obfs4"), ("snowflake", "Snowflake"), ("custom", "My bridges")])
        + f'''<div class="item" style="display:block"><div class="d" style="margin:0 0 10px">Your own bridges, one per line, from bridges.torproject.org. Lines that don't look like bridges are ignored.</div>
<textarea class="inp" id="pbr" spellcheck="false" placeholder="obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=... iat-mode=0">{esc(c["proxy_bridges"])}</textarea><div style="margin-top:10px"><button class="btn" id="savebr">Save bridges</button></div></div>''')
    rules = ""
    for host, rl in sorted(c["site_rules"].items()):
        for r in rl:
            label = {"nojs": "JavaScript blocked", "http": "Plain HTTP allowed", "noblock": "Ad and tracker blocking off"}.get(r, r)
            rules += (f'<div class="item"><div class="grow"><div class="t">{esc(host)}</div><div class="d">{label}</div></div>'
                      f'<button class="btn dng ghost" data-delrule data-h="{esc(host)}" data-r="{r}">Remove</button></div>')
    if not rules:
        rules = '<div class="empty">No site rules yet. You can also set them from the lock icon in the address bar.</div>'
    blocklist = esc("\n".join(c["custom_blocklist"]))
    clear_btns = "".join(f'<button class="btn" data-clear="{k}">{n}</button>' for k, n in
                         (("history", "History"), ("cookies", "Cookies"), ("cache", "Cache"), ("downloads", "Download list")))
    body = f"""
<h1>Settings</h1><p class="lede">Everything stays on this computer. Shield has no accounts, sync, telemetry or crash reporting.</p>
<h2>General</h2><div class="group">{general}</div>
<h2>Privacy and security</h2><div class="group">{privacy}</div>
<h2>Private connection</h2><div class="group">{proxy}</div>
<h2 id="lists">Protection lists</h2><div class="group">{lists}</div>
<h2>Passwords</h2><div class="group">{pw}</div>
<h2>Permissions</h2><div class="group">{perms}</div>
<h2>Downloads</h2><div class="group">{dl}</div>
<h2 id="scanning">Scanners</h2><div class="group">{scan_rows}</div>
<h2>VirusTotal</h2><div class="group">{vt}</div>
<h2>Site rules</h2><div class="group">{rules}
<div class="item"><div class="grow"><input class="inp" type="text" id="rh" placeholder="example.com" size="24" spellcheck="false"></div>
<div class="ctl"><div class="seg" id="rr"><button data-v="nojs" class="on">Block JavaScript</button><button data-v="http">Allow plain HTTP</button><button data-v="noblock">Blocking off</button></div><button class="btn pri" id="addrule">Add</button></div></div></div>
<h2>Blocked sites</h2><div class="group"><div class="item" style="display:block"><div class="d" style="margin:0 0 10px">One domain per line. Subresources are blocked everywhere and top-level visits get a warning page.</div>
<textarea class="inp" id="bl" spellcheck="false">{blocklist}</textarea><div style="margin-top:10px"><button class="btn" id="savebl">Save list</button></div></div></div>
<h2 id="clear">Clear data</h2><div class="group"><div class="item"><div class="grow" style="display:flex;gap:8px;flex-wrap:wrap">{clear_btns}</div>
<button class="btn dng" data-clear="all">Clear everything</button></div></div>
<h2>Updates</h2><div class="group">{upd}</div>
<h2>About</h2><div class="group">{_item(f"Shield {VERSION}", f"Chromium {esc(ctx.engine['chromium'])} (Qt WebEngine). " + ("The engine is updated with each Shield release, so installing updates matters more than any setting here." if getattr(sys, "frozen", False) else "Update PyQt6-WebEngine regularly: engine patches matter more than any setting here."))}
{_item("Data folder", "", f'<span class="mono">{esc(str(HOME))}</span>')}</div>
"""
    script = r"""
const save=async(k,v,el)=>{const r=await api("set",{k,v});
 if(r.ok){toast(r.note||"Saved");if(k==="theme"&&r.theme)document.documentElement.dataset.theme=r.theme}else{toast("Not saved: invalid value");if(el&&el.type==="checkbox")el.checked=!el.checked}};
$$("input[data-k]").forEach(el=>el.addEventListener("change",()=>save(el.dataset.k,el.type==="checkbox"?(el.checked?"1":"0"):el.value.trim(),el)));
$$("select[data-k]").forEach(el=>el.addEventListener("change",()=>save(el.dataset.k,el.value)));
$$(".seg[data-k]").forEach(el=>seg(el,v=>save(el.dataset.k,v)));seg($("#rr"));
$("#addrule").onclick=async()=>{const hst=$("#rh").value.trim().toLowerCase();if(!hst)return;const r=await api("site/add",{host:hst,rule:$("#rr .on").dataset.v});if(r.ok)location.reload();else toast("That isn't a valid host")};
$$("[data-delrule]").forEach(b=>b.onclick=async()=>{await api("site/del",{host:b.dataset.h,rule:b.dataset.r});location.reload()});
$("#savebl").onclick=async()=>{await api("blocklist",{text:$("#bl").value});toast("List saved")};
$("#savebr").onclick=async()=>{const r=await api("proxy/bridges",{text:$("#pbr").value});
 if(!r.ok){toast("Not saved");return}
 toast(r.count?(r.count+(r.count===1?" bridge":" bridges")+" saved"+(r.bad?", "+r.bad+" line"+(r.bad===1?"":"s")+" ignored":"")):(r.bad?"None of those look like bridge lines":"Bridges cleared"))};
$$("[data-clear]").forEach(b=>b.onclick=async()=>{const k=b.dataset.clear;
 if(k==="all"){const a=await sheet({icon:"trash",tone:"bad",title:"Clear everything?",body:"This removes history, cookies, cached files and the download list. Files you've already downloaded stay where they are.",actions:[{label:"Clear everything",kind:"dng fill",value:"ok"},{label:"Cancel",kind:"ghost",value:null}]});if(a!=="ok")return}
 await api("clear",{what:k});toast("Cleared")});
async function askKey(){const r=await sheet({icon:"key",title:"VirusTotal API key",body:"Paste the key from your VirusTotal profile. It's saved on this computer only and sent only to virustotal.com.",field:{type:"password",placeholder:"64-character key"},
 actions:[{label:"Save key",kind:"pri",value:"save"},{label:"Cancel",kind:"ghost",value:null}]});
 if(!r||r.action!=="save")return;const k=(r.value||"").trim();if(!k)return;const s=await api("vt/key",{key:k});if(s.ok){toast("Key saved");setTimeout(()=>location.reload(),600)}else toast("That doesn't look like a VirusTotal key")}
$("#vtchange").onclick=askKey;
const rm=$("#vtremove");if(rm)rm.onclick=async()=>{await api("vt/key",{key:""});toast("Key removed");setTimeout(()=>location.reload(),500)};
$$("[data-update]").forEach(b=>b.onclick=async()=>{const k=b.dataset.update,old=b.textContent;b.disabled=true;b.textContent="Working";
 const r=await api("engine/update",{key:k});if(!r.ok){toast(r.err||"Couldn't start");b.disabled=false;b.textContent=old;return}
 for(;;){await sleep(900);const e=(await api("engines")).engines?.find(x=>x.key===k);if(!e)break;const d=$(`[data-eng="${k}"]`);if(d)d.textContent=e.msg&&e.busy?e.msg:e.detail;
  if(!e.busy){if(e.err)toast(e.err);else toast(e.name+" is up to date");b.disabled=false;b.textContent="Update";break}}});
$$("input[data-list]").forEach(el=>el.addEventListener("change",async()=>{const r=await api("list/set",{id:el.dataset.list,on:el.checked?"1":"0"});
 if(!r.ok){toast("Not saved");el.checked=!el.checked;return}toast(el.checked?"List turned on. Updating":"List turned off");pollLists(true)}));
async function pollLists(kick){if(kick)await api("lists/update");const b=$("#lstupd");b.disabled=true;b.textContent="Updating";
 for(let i=0;i<400;i++){await sleep(900);const r=await api("lists");if(!r.ok)break;
  r.lists.forEach(l=>{const e=$(`[data-lst="${l.id}"]`);if(e)e.textContent=l.line});$("#lstsum").textContent=r.summary;
  if(!r.busy){if(r.err)toast(r.err);else if(kick||i>0)toast("Lists are up to date");break}}
 b.disabled=false;b.textContent="Update lists"}
$("#lstupd").onclick=()=>pollLists(true);
async function loadUpd(force){const r=await api(force?"update/check":"update/state");if(!r.ok){$("#engline").textContent=r.err||"Couldn't check";return}
 $("#engline").textContent=r.engine;const a=$("#appline");if(a){a.textContent=r.app||"Not checked yet";const c=$("#appctl");c.textContent="";
  if(r.app_new){const lab=r.can_install?"Install and restart":"Download";const b=h("button",{class:"btn pri",onclick:async()=>{b.disabled=true;b.textContent=r.can_install?"Updating":"Downloading";const d=await api("update/download");if(!d.ok||!r.can_install){b.disabled=false;b.textContent=lab}toast(d.ok?(d.msg||"Downloading"):(d.err||"Download failed"))}},lab);c.append(b)}}}
$("#updchk").onclick=async()=>{const b=$("#updchk");b.disabled=true;await loadUpd(true);b.disabled=false};
loadUpd(false);
if(location.hash)setTimeout(()=>{const t=$(location.hash);t&&t.scrollIntoView({behavior:"smooth"})},300);
"""
    return shell(ctx, "Settings", body, script, nav="settings")


# --------------------------------------------------------------------------
# Security center
# --------------------------------------------------------------------------
LAYERS = [
    ("Download gate", lambda c: True, "Approval, quarantine, signature check, scanners, disguise detection and VirusTotal on request."),
    ("HTTPS-only", lambda c: c["https_only"], "Plain-HTTP requests are upgraded. Failures show a warning, never a silent downgrade."),
    ("Strict TLS", lambda c: True, "Invalid or expired certificates are always rejected. There is no click-through."),
    ("Ad and tracker blocking", lambda c: c["block_trackers"], "Requests are checked against regularly updated protection lists and dropped."),
    ("YouTube ad blocking", lambda c: c["block_youtube_ads"], "Video ads are removed from the data YouTube's player is given, with a speed-up-and-skip fallback if one still starts."),
    ("Harmful-site warnings", lambda c: c["block_harmful"], "Known phishing, malware and scam pages are caught before they open, using lists matched on this computer."),
    ("Link cleaning", lambda c: c["clean_links"], "Tracking parameters and click-counting redirects are removed from links you follow."),
    ("Third-party cookie blocking", lambda c: c["block_third_party_cookies"], "Cross-site cookies are refused."),
    ("Local network shield", lambda c: c["block_local_network"], "Websites cannot reach localhost or your LAN."),
    ("Fingerprint protection", lambda c: c["fingerprint_protection"], "Normalized hints plus noise that is different for every site."),
    ("Navigation guard", lambda c: c["navigation_guard"], "Lookalike, international-character and blocked-site warnings."),
    ("Permission broker", lambda c: True, "Camera, mic, location and others: deny by default or ask, with session-only grants."),
    ("Process isolation", lambda c: True, "Site-per-process and strict origin isolation, Chromium sandbox on."),
    ("Hardened mode (no JIT)", lambda c: c["hardened_mode"], "JavaScript runs without the JIT compiler, closing the biggest class of browser exploits. Slower pages. Off by default."),
    ("Hardened internal pages", lambda c: True, "Private scheme, secret tokens, strict CSP, escaped output."),
    ("No tracking of you", lambda c: True, "No accounts, sync, usage stats or crash uploads. The only background requests fetch protection lists and update checks, and you can switch both off."),
]


def page_security(ctx, q):
    c = ctx.cfg
    active = sum(1 for _, fn, _ in LAYERS if fn(c))
    rows = ""
    for name, fn, desc in LAYERS:
        on = fn(c)
        rows += (f'<div class="item"><span class="row-ic" style="color:var(--{"ok" if on else "warn"})">{ic("check" if on else "alert", 17)}</span>'
                 f'<div class="grow"><div class="t">{name}</div><div class="d">{desc}</div></div>'
                 f'<span class="chip {"ok" if on else "warn"}">{"Active" if on else "Off"}</span></div>')
    all_on = active == len(LAYERS)
    hero = (f'<div class="hero" style="{"" if all_on else "background:linear-gradient(135deg,color-mix(in srgb,var(--warn) 17%,var(--surface)),var(--surface) 75%)"}">'
            f'<div class="orb" style="{"" if all_on else "color:var(--warn);background:color-mix(in srgb,var(--warn) 20%,transparent)"}">{ic("shield-check" if all_on else "shield-alert", 30)}</div>'
            f'<div><h3>{"Protection is on" if all_on else "Some protection is off"}</h3><p>{active} of {len(LAYERS)} protection layers are active.</p></div></div>')
    body = f"""
<h1>Security center</h1><p class="lede">What Shield blocked this session. This log lives in memory only and disappears when you quit.</p>
{hero}
<div class="stats" id="stats"></div>
<h2>Protection layers</h2><div class="group">{rows}</div>
<h2>Protection lists</h2><div class="group">{_item("Loaded now", f'<span id="prot">{esc(_summary_line(ctx.app.protection_summary() if ctx.app else {}))}</span>', '<a class="btn" href="shield://settings#lists">Manage</a>')}</div>
<h2>Engine</h2><div class="group">{_item(f"Chromium {esc(ctx.engine['chromium'])}", f'<span class="mono">{esc(ctx.engine["flags"])}</span>')}
{_item("Web engine version", '<span id="engline">Checking</span>')}
{_item("Chromium sandbox", "The engine's own security sandbox for web pages.", f'<span class="chip {"ok" if ctx.engine.get("sandbox") == "on" else "bad"}">{"On" if ctx.engine.get("sandbox") == "on" else "OFF"}</span>')}
{"".join(_item("Startup warning", esc(w)) for w in ctx.engine.get("warnings", []))}</div>
<h2>Most blocked domains</h2><div class="group" id="doms"></div>
<h2>Recent events</h2><div class="group" id="log"></div>
"""
    script = r"""
const LABELS={tracker:"Trackers blocked",harmful:"Harmful sites stopped",link:"Links cleaned",cookie:"Cookies blocked",https_upgrade:"HTTPS upgrades",local_net:"LAN probes blocked",permission:"Permissions denied",download:"Download decisions",navigation:"Navigation warnings",tls:"Bad certificates",popup:"Popups limited"};
const st=$("#stats");for(const k in LABELS){const b=h("b",{"data-v":"0"},"0");st.append(h("div",{class:"stat","data-k":k},b,h("span",{},LABELS[k])))}
const seen=new Set();
function fill(id,rows,mk,empty){const t=$("#"+id);if(!rows.length){if(!t.dataset.e){t.textContent="";t.append(h("div",{class:"empty"},empty));t.dataset.e=1}return}
 if(t.dataset.e){t.textContent="";delete t.dataset.e}t.textContent="";rows.forEach(r=>t.append(mk(r)))}
async function load(){const r=await api("events");if(!r.counts)return;
 $$(".stat").forEach(s=>countUp($("b",s),r.counts[s.dataset.k]||0));
 fill("doms",r.domains,([d,n])=>h("div",{class:"item"},h("div",{class:"grow mono",style:"color:var(--text)"},d),h("span",{class:"chip"},n+"x")),"Nothing blocked yet");
 const t=$("#log");const fresh=r.log.map(e=>e.t+e.kind+e.detail);
 fill("log",r.log.slice(0,40),e=>{const key=e.t+e.kind+e.detail,row=h("div",{class:"item",style:seen.has(key)?"":"animation:fade .6s var(--ease)"},
  h("span",{class:"mono",style:"width:64px;flex:none"},e.t),h("span",{class:"chip"},LABELS[e.kind]||e.kind),h("div",{class:"grow mono",style:"color:var(--text)"},e.detail));seen.add(key);return row},"Nothing yet this session")}
load();setInterval(load,2000);
api("update/state").then(r=>{$("#engline").textContent=r.ok?r.engine:(r.err||"Couldn't check")});
"""
    return shell(ctx, "Security center", body, script, nav="security")


# --------------------------------------------------------------------------
# Downloads (rendered live in the page so progress and scan results animate instead of reloading)
# --------------------------------------------------------------------------
def page_downloads(ctx, q):
    body = ('<h1>Downloads</h1><p class="lede">New files wait in quarantine while Shield checks who made them and scans them. '
            'Release one and it moves to your Downloads folder.</p><div id="list"></div><div class="empty" id="none" style="display:none">'
            f'<div class="row-ic" style="margin:0 auto 12px;width:46px;height:46px">{ic("download", 22)}</div>No downloads yet.</div>')
    script = r"""
const KIND={program:"window",installer:"archive",script:"terminal",archive:"archive",document:"file",media:"image",diskimage:"archive",macro:"file",text:"file",file:"file"};
const TONE={trusted:["shield-check","ok"],clean:["shield-check","ok"],checked:["shield-check","info"],unverified:["shield","info"],caution:["alert","warn"],danger:["shield-alert","bad"],malicious:["shield-alert","bad"]};
const LV={good:["check","good"],info:["info","info"],warn:["alert","warn"],bad:["shield-alert","bad"]};
const STATE={downloading:["Downloading","acc"],scanning:["Scanning","acc"],quarantined:["Quarantined",""],released:["Released","ok"],failed:["Failed","bad"],blocked:["Blocked","bad"],missing:["Missing","warn"],deleted:["Deleted",""]};
const cards=new Map(),open=new Set();let timer;
const tone=v=>TONE[v]||["info","info"];
function vtBlock(d){const v=d.vt,l=d.vtlive,id=d.id;
 const run=(up)=>async()=>{let r=await api("vt/scan",{id,upload:up?"1":"0"});if(r.err==="nokey"){const k=await sheet({icon:"key",title:"Add a VirusTotal key",body:"Looking files up needs a free VirusTotal API key. It stays on this computer.",field:{type:"password",placeholder:"64-character key"},actions:[{label:"Save and continue",kind:"pri",value:"save"},{label:"Cancel",kind:"ghost",value:null}]});
   if(!k||k.action!=="save"||!(k.value||"").trim())return;const s=await api("vt/key",{key:k.value.trim()});if(!s.ok){toast("That doesn't look like a VirusTotal key");return}r=await api("vt/scan",{id,upload:up?"1":"0"})}
  if(!r.ok&&r.err)toast(r.err);poll(true)};
 const wrap=(...k)=>h("div",{},h("h5",{},"VirusTotal"),...k);
 if(l)return wrap(h("div",{class:"vt"},h("div",{class:"ring"}),h("div",{class:"grow"},h("div",{class:"t"},l.label||"Working"),h("div",{class:"d"},"Free keys are limited to a few requests a minute, so this can take a little while.")),h("button",{class:"btn",onclick:async()=>{await api("vt/cancel",{id});poll(true)}},"Cancel")));
 if(!v)return wrap(h("div",{class:"vt"},h("div",{class:"grow"},h("div",{class:"t"},"Not checked yet"),h("div",{class:"d"},"Looks the file up by its fingerprint. If VirusTotal hasn't seen it, you choose whether to upload it.")),h("button",{class:"btn pri",onclick:run(false)},"Check on VirusTotal")));
 if(v.state==="needs_upload")return wrap(h("div",{class:"vt",style:"flex-wrap:wrap"},h("div",{class:"grow"},h("div",{class:"t"},"VirusTotal hasn't seen this file"),h("div",{class:"d"},"To scan it, Shield has to upload it. Uploaded files can be viewed by VirusTotal and the security companies it works with. "+fmtSize(v.size)+".")),h("button",{class:"btn pri",onclick:run(true)},ic("upload",15),"Upload and scan")));
 if(v.state==="error")return wrap(h("div",{class:"vt"},h("span",{style:"color:var(--warn)"},ic("alert",20)),h("div",{class:"grow"},h("div",{class:"t"},"Couldn't finish"),h("div",{class:"d"},v.error||"Something went wrong.")),h("button",{class:"btn",onclick:run(false)},"Try again")));
 const bad=v.malicious+v.suspicious,col=v.malicious?"bad":v.suspicious?"warn":"ok";
 return wrap(h("div",{class:"vt"},h("div",{class:"big",style:`color:var(--${col})`},String(bad),h("small",{}," / "+v.total)),h("div",{class:"grow"},h("div",{class:"t"},bad?(v.malicious+" engine"+(v.malicious===1?"":"s")+" flagged this file"+(v.suspicious?`, ${v.suspicious} suspicious`:"")):"No engine flagged this file"),
  h("div",{class:"d"},(v.source==="existing"?"Existing report":"Fresh scan")+(v.date?", "+new Date(v.date*1000).toLocaleDateString():""))),h("a",{class:"btn",target:"_blank",href:v.link},ic("external",14),"Full report")),
  v.flagged&&v.flagged.length?h("div",{style:"margin-top:8px"},v.flagged.slice(0,8).map(f=>h("div",{class:"fr "+(f.category==="malicious"?"bad":"warn")},ic("shield-alert",16),h("div",{},f.engine,h("small",{},f.result||f.category))))):null)}
function details(d){const s=d.scan,k=[];
 if(s){const f=s.findings||[];if(s.signature&&s.signature.status&&s.signature.status!=="unsupported"){}
  if(f.length){k.push(h("h5",{},"What Shield found"));f.forEach(x=>{const [i,c]=LV[x.level]||LV.info;k.push(h("div",{class:"fr "+c},ic(i,16),h("div",{},x.title,x.detail?h("small",{},x.detail):null)))})}
  const en=s.engines||[];if(en.length){k.push(h("h5",{},"Scanners"));en.forEach(e=>k.push(h("div",{class:"fr "+(e.state==="found"?"bad":e.state==="clean"?"good":e.state==="error"?"warn":"info")},ic(e.state==="found"?"shield-alert":e.state==="clean"?"check":e.state==="error"?"alert":"info",16),h("div",{},e.name,h("small",{},e.state==="clean"?"Nothing found":e.detail)))))}}
 if(d.sha256){k.push(h("h5",{},"SHA-256"),h("div",{style:"display:flex;gap:8px;align-items:flex-start"},h("div",{class:"mono grow"},d.sha256),h("button",{class:"btn icon ghost",title:"Copy",onclick:async()=>{try{await navigator.clipboard.writeText(d.sha256);toast("Copied")}catch(e){toast("Select the text to copy it")}}},ic("copy",15))));
  if(d.url)k.push(h("h5",{},"Source"),h("div",{class:"mono"},d.url))}
 if(d.state==="quarantined"||d.state==="released")k.push(vtBlock(d));
 return k}
function actions(d){const id=d.id,a=[];const folder=h("button",{class:"btn icon ghost",title:"Show in folder",onclick:()=>api("download/folder",{id})},ic("folder",16));
 const del=h("button",{class:"btn ghost dng",onclick:()=>{collapse(id);api("download/delete",{id})}},ic("trash",15),"Delete");
 if(d.state==="quarantined"){const risky=d.verdict==="danger"||d.verdict==="malicious";
  a.push(h("button",{class:"btn "+(risky?"dng":"pri"),onclick:async()=>{let r=await api("download/release",{id});
   if(!r.ok&&r.err==="confirm"){const x=await sheet({icon:"shield-alert",tone:"bad",title:d.verdict==="danger"||d.verdict==="malicious"?"Release a flagged file?":"Release a file Shield couldn't vouch for?",body:d.verdict==="malicious"?"A scanner identified this file as malware. Releasing it moves it out of quarantine, where it can run.":d.verdict==="danger"?"Shield found signs this file is disguised or unsafe. Releasing it moves it out of quarantine, where it can run.":"Shield couldn't confirm this file is safe: it may be unsigned and unknown, only partly checked, or have come with a warning. Only release it if you trust where it came from.",actions:[{label:"Release anyway",kind:"dng fill",value:"ok"},{label:"Keep in quarantine",kind:"ghost",value:null}]});if(x!=="ok")return;r=await api("download/release",{id,confirm:"1"})}
   if(r.ok){toast("Released to Downloads");poll(true)}else toast(r.err||"Couldn't release")}},"Release"),del,folder)}
 else if(d.state==="released")a.push(folder);
 else if(d.state==="scanning"||d.state==="downloading"){}
 else a.push(h("button",{class:"btn ghost",onclick:()=>{collapse(id);api("download/forget",{id})}},"Remove"));
 return a}
function verdictBox(d){if(d.state==="scanning")return h("div",{class:"verdict tone-info"},h("div",{class:"bd"},h("div",{class:"ring"})),h("div",{},h("h4",{},"Scanning"),h("p",{},(d.live&&d.live.label)||"Checking the file")));
 const s=d.scan;if(!s)return null;const [i,t]=tone(s.verdict);
 return h("div",{class:"verdict tone-"+t},h("div",{class:"bd"},ic(i,20)),h("div",{},h("h4",{},s.headline),h("p",{},s.summary),
  (s.engines||[]).every(e=>e.state==="skipped")?h("p",{style:"margin-top:8px"},h("a",{href:"shield://settings#scanning"},"Set up scanners")):null))}
function make(d){const el=h("div",{class:"col gap"}),inner=h("div",{class:"in"}),card=h("div",{class:"dl"});el.append(inner);inner.append(card);
 const c={el,card,id:d.id,sig:"",psig:""};cards.set(d.id,c);return c}
function fill(c,d){const sig=JSON.stringify([d.state,d.verdict,d.scan,d.vt,d.live,d.vtlive,d.name,open.has(d.id)]);
 if(d.state==="downloading"){const p=d.progress||{},pct=p.total>0?Math.min(100,p.received*100/p.total):null;
  if(c.bar){c.bar.className="bar"+(pct==null?" ind":"");c.bar.firstChild.style.width=pct==null?"":pct+"%"}
  if(c.meta)c.meta.textContent=[d.host,pct==null?fmtSize(p.received):fmtSize(p.received)+" of "+fmtSize(p.total)].filter(Boolean).join("  ·  ")}
 if(sig===c.sig)return;c.sig=sig;const card=c.card;card.textContent="";
 const [sl,sc]=STATE[d.state]||[d.state,""];const meta=h("div",{class:"mt"},[d.host,d.size?fmtSize(d.size):"",ago(d.ts)].filter(Boolean).join("  ·  "));c.meta=meta;
 const isOpen=open.has(d.id),can=d.state==="quarantined"||d.state==="released";
 const head=h("div",{class:"dl-h"},h("div",{class:"fi"},ic(KIND[d.kind]||"file",21)),h("div",{class:"grow",style:"min-width:0"},h("div",{class:"nm"},h("span",{class:"n"},d.name),h("span",{class:"chip "+sc},sl)),meta),h("div",{class:"acts"},actions(d)));
 card.append(head);
 if(d.state==="downloading"){c.bar=h("div",{class:"bar"},h("i"));card.append(c.bar);fill(c,d);return}else c.bar=null;
 const vb=verdictBox(d);if(vb)card.append(vb);
 (d.flags||[]).filter(f=>!d.scan).forEach(f=>card.append(h("div",{class:"verdict tone-"+(f[0]==="danger"?"bad":"warn")},h("div",{class:"bd"},ic(f[0]==="danger"?"shield-alert":"alert",18)),h("div",{},h("p",{style:"margin:0"},f[1])))));
 if(can||d.scan){const body=h("div",{class:"pane"},details(d)),more=h("div",{class:"more"+(isOpen?" open":"")},h("div",{},body));
  const lab=h("span",{},isOpen?"Hide details":"Details"),chev=h("span",{class:"tog"+(isOpen?" up":""),style:"display:inline-flex"},ic("chevron-down",14));
  const tog=h("button",{class:"btn ghost",style:"width:100%;justify-content:center;border-radius:0 0 14px 14px;color:var(--mut)",onclick:()=>{const o=more.classList.toggle("open");o?open.add(d.id):open.delete(d.id);chev.classList.toggle("up",o);lab.textContent=o?"Hide details":"Details";c.sig=c.sig.replace(/,(true|false)\]$/,","+o+"]")}},lab,chev);
  card.append(h("div",{style:"border-top:1px solid var(--line)"},tog),more)}}
function collapse(id){const c=cards.get(id);if(!c)return;c.el.classList.add("gone");setTimeout(()=>{c.el.remove();cards.delete(id);$("#none").style.display=cards.size?"none":"block"},520)}
function render(list){const wrap=$("#list"),seen=new Set();
 list.forEach((d,i)=>{seen.add(d.id);let c=cards.get(d.id);if(!c||c.el.classList.contains("gone")){if(c)return;c=make(d);wrap.insertBefore(c.el,wrap.children[i]||null);c.el.animate([{opacity:0,transform:"translateY(10px)"},{opacity:1,transform:"none"}],{duration:520,easing:"cubic-bezier(.22,1,.36,1)"})}fill(c,d)});
 for(const [id,c] of [...cards])if(!seen.has(id))collapse(id);
 $("#none").style.display=list.length?"none":"block"}
async function poll(now){clearTimeout(timer);const r=await api("downloads");if(r.downloads){render(r.downloads);
 const busy=r.downloads.some(d=>d.state==="downloading"||d.state==="scanning"||d.vtlive);timer=setTimeout(poll,busy?700:3500)}else timer=setTimeout(poll,5000)}
poll();
"""
    return shell(ctx, "Downloads", body, script, nav="downloads")


# --------------------------------------------------------------------------
# History / bookmarks
# --------------------------------------------------------------------------
def _searchbox(placeholder, extra=""):
    return f'<div class="find">{ic("search", 16)}<input type="text" id="s" placeholder="{esc(placeholder)}" autocomplete="off" spellcheck="false">{extra}</div>'


FILTER_JS = r"""
const s=$("#s"),rows=$$("[data-text]");let ft;
s.addEventListener("input",()=>{clearTimeout(ft);ft=setTimeout(()=>{const q=s.value.trim().toLowerCase();let n=0;
 rows.forEach(r=>{const m=!q||r.dataset.text.includes(q);r.style.display=m?"":"none";if(m)n++});
 $$("[data-day]").forEach(d=>{let el=d.nextElementSibling,any=false;while(el&&!el.dataset.day){if(el.style.display!=="none")any=true;el=el.nextElementSibling}d.style.display=any?"":"none"});
 $("#nomatch").style.display=n||!rows.length?"none":"block"},90)});
document.addEventListener("keydown",e=>{if(e.key==="/"&&document.activeElement!==s){e.preventDefault();s.focus()}else if(e.key==="Escape"&&s.value){s.value="";s.dispatchEvent(new Event("input"))}});
function gone(row,fn){const done=()=>{row.remove();fn&&fn()};if(!row.animate||matchMedia("(prefers-reduced-motion:reduce)").matches){done();return}const h0=row.getBoundingClientRect().height;row.style.overflow="hidden";row.style.pointerEvents="none";const a=row.animate([{height:h0+"px",opacity:1,transform:"none"},{height:"0px",opacity:0,paddingTop:"0px",paddingBottom:"0px",marginTop:"0px",marginBottom:"0px",transform:"translateX(-8px)"}],{duration:340,easing:"cubic-bezier(.22,1,.36,1)",fill:"forwards"});a.onfinish=done;a.oncancel=done}
"""


def page_history(ctx, q):
    items = ctx.store.history("")
    out, last_day, open_group = "", None, False
    for h in items:
        d = day_label(h["ts"])
        if d != last_day:
            if open_group:
                out += "</div>"
            out += f'<h2 data-day="1">{esc(d)}</h2><div class="group">'
            open_group, last_day = True, d
        title = (h["title"] or h["url"])[:90]
        out += (f'<div class="item" data-text="{esc((title + " " + h["url"]).lower())}">{fav_html(ctx, h["url"])}'
                f'<div class="grow" style="min-width:0"><a href="{esc(h["url"])}" class="t" style="display:block;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(title)}</a>'
                f'<div class="d" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(h["url"][:110])}</div></div>'
                f'<span class="d" style="margin:0">{time.strftime("%H:%M", time.localtime(h["ts"]))}</span>'
                f'<button class="btn icon ghost hide" title="Remove" data-h="{h["id"]}">{ic("close", 15)}</button></div>')
    if open_group:
        out += "</div>"
    if not out:
        out = f'<div class="group"><div class="empty">{"History is turned off in Settings." if not ctx.cfg["history_days"] else "Nothing here yet."}</div></div>'
    clr = '<button class="btn dng ghost" id="clr">Clear all</button>'
    body = (f'<h1>History</h1><p class="lede">Pages you visit are kept only on this computer.</p>'
            f'{_searchbox("Search history", clr)}'
            f'<div id="items">{out}</div><div class="empty" id="nomatch" style="display:none">No matches.</div>')
    script = FILTER_JS + r"""
$("#clr").onclick=async()=>{const a=await sheet({icon:"trash",tone:"bad",title:"Clear all history?",body:"This removes every page from your history. It can't be undone.",actions:[{label:"Clear history",kind:"dng fill",value:"ok"},{label:"Cancel",kind:"ghost",value:null}]});
 if(a!=="ok")return;await api("clear",{what:"history"});location.reload()};
$$("[data-h]").forEach(b=>b.onclick=async()=>{await api("history/del",{id:b.dataset.h});gone(b.closest(".item"))});
"""
    return shell(ctx, "History", body, script, nav="history")


def page_bookmarks(ctx, q):
    rows = ""
    for b in ctx.store.bookmarks():
        title = (b["title"] or b["url"])[:90]
        rows += (f'<div class="item" data-text="{esc((title + " " + b["url"]).lower())}">{fav_html(ctx, b["url"])}'
                 f'<div class="grow" style="min-width:0"><a href="{esc(b["url"])}" class="t" style="display:block;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(title)}</a>'
                 f'<div class="d" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(b["url"][:110])}</div></div>'
                 f'<button class="btn icon ghost hide" title="Remove" data-u="{esc(b["url"])}">{ic("close", 15)}</button></div>')
    if not rows:
        rows = '<div class="empty">No bookmarks yet. Press Ctrl+D on any page.</div>'
    body = (f'<h1>Bookmarks</h1><p class="lede">Saved pages, stored only on this computer.</p>{_searchbox("Search bookmarks")}'
            f'<div style="height:10px"></div><div class="group" id="items">{rows}</div><div class="empty" id="nomatch" style="display:none">No matches.</div>')
    script = FILTER_JS + r"""
$$("[data-u]").forEach(b=>b.onclick=async()=>{await api("bookmark/del",{url:b.dataset.u});gone(b.closest(".item"))});
"""
    return shell(ctx, "Bookmarks", body, script, nav="bookmarks")


# --------------------------------------------------------------------------
# New tab + warning
# --------------------------------------------------------------------------
def page_newtab(ctx, q):
    name, tmpl = SEARCH_ENGINES[ctx.cfg["search_engine"]]
    action = tmpl.split("?")[0]
    tiles = ""
    for b in ctx.store.bookmarks(12):
        host = urlparse(b["url"]).hostname or "?"
        label = (b["title"] or host)[:20]
        tiles += f'<a class="tile" href="{esc(b["url"])}">{fav_html(ctx, b["url"])}<span class="l">{esc(label)}</span></a>'
    n = sum(ctx.events.counts.get(k, 0) for k in ("tracker", "cookie", "local_net"))
    body = (f'<div class="center"><div class="logo"><span class="mk">{ic("shield-check", 30, "")}</span>Shield</div>'
            f'<form action="{esc(action)}" method="get" class="search">{ic("search", 20)}<input type="text" name="q" autofocus autocomplete="off" '
            f'placeholder="Search with {esc(name)} or enter an address"></form>'
            f'<div class="tiles">{tiles}</div></div>'
            f'<div class="foot">{n:,} trackers and probes blocked this session &nbsp;&middot;&nbsp; <a href="shield://security">Security center</a> '
            f'&nbsp;&middot;&nbsp; <a href="shield://settings">Settings</a></div>')
    return shell(ctx, "New tab", body)


WARN_TEXT = {
    "idn": ("This address uses special characters",
            "The address <b>{shown}</b> contains international characters. Attackers use look-alike letters to imitate real sites and steal logins."),
    "lookalike": ("This looks like a fake site",
                  "<b>{host}</b> is almost identical to <b>{real}</b>. Lookalike domains are a common way to steal passwords."),
    "blocked": ("You blocked this site", "<b>{host}</b> is on your personal block list."),
    "phishing": ("This page is a known phishing site",
                 "<b>{host}</b> is on a live list of pages built to steal passwords and payment details. Don't enter anything on it."),
    "malware": ("This site is known to spread malware",
                "<b>{host}</b> is on a live list of addresses that are serving malware right now. Opening it can infect your computer."),
    "scam": ("This site is reported as a scam",
             "<b>{host}</b> is on a list of scam, fake-download and malicious sites. It's very likely not what it claims to be."),
    "nohttps": ("Couldn't make a secure connection",
                "<b>{host}</b> didn't load over HTTPS. Either the site doesn't support secure connections, or the connection failed. "
                "If you continue over plain HTTP, anyone on the network can read or change what you send and receive."),
}


def page_warning(ctx, q):
    kind, url = q.get("kind", ""), q.get("url", "")
    p = urlparse(url)
    if kind not in WARN_TEXT or p.scheme not in ("http", "https") or not p.hostname:
        return shell(ctx, "Warning", '<div class="center"><h1>Nothing to show</h1></div>')
    title, text = WARN_TEXT[kind]
    text = text.format(shown=esc(q.get("d") or p.hostname), host=esc(p.hostname), real=esc(q.get("d", "")))
    body = (f'<div class="center"><div class="warnbox"><div class="bd">{ic("shield-alert", 34)}</div><h1>{esc(title)}</h1><p>{text}</p>'
            f'<div class="mono">{esc(url[:200])}</div><div style="display:flex;gap:10px"><button class="btn pri lg" id="back">Go back</button>'
            f'<button class="btn lg ghost" id="go">Continue anyway</button></div></div></div>')
    script = ("const U=%s,K=%s,H=%s;"
              "$('#back').onclick=()=>{if(history.length>1)history.back();else location.href='shield://newtab'};"
              "$('#go').onclick=async()=>{await api('allow',{kind:K,host:H});location.href=U};"
              % (json.dumps(url), json.dumps(kind), json.dumps(p.hostname)))
    return shell(ctx, "Warning", body, script)


# --------------------------------------------------------------------------
# Passwords (rendered live in the page: the vault locks and unlocks without reloading)
# --------------------------------------------------------------------------
def page_passwords(ctx, q):
    body = ('<h1>Passwords</h1><p class="lede">Logins are encrypted with your master password and kept only on this computer. '
            'Nothing is synced or uploaded.</p><div id="root"></div>')
    script = r"""
const root=$("#root");let S=null,LIST=[],NEVER=[],AUD=null,Q="",ONLY=null;
const meter=()=>h("div",{class:"meter","data-s":"0"},[0,1,2,3,4].map(()=>h("i")));
const watch=(inp,m)=>inp.addEventListener("input",()=>{clearTimeout(m._t);m._t=setTimeout(async()=>{const r=await api("vault/strength",{pw:inp.value});if(r.ok)m.dataset.s=inp.value?r.score:"0"},120)});
function modal({icon="key",tone="",title,lede="",fields=[],label="Save",danger=false,submit}){return new Promise(res=>{
 const inputs={},err=h("div",{class:"err"});
 const close=async v=>{bg.classList.remove("on");document.removeEventListener("keydown",key,true);await sleep(320);bg.remove();res(v)};
 const rows=fields.map(f=>{const inp=h("input",{class:"inp",type:f.type||"text",value:f.value||"",placeholder:f.placeholder||"",autocomplete:"off",spellcheck:"false"});inputs[f.key]=inp;const extra=[];
  if(f.type==="password"){const eye=h("button",{class:"btn icon",type:"button",title:"Show or hide",onclick:()=>{const on=inp.type==="password";inp.type=on?"text":"password";eye.replaceChildren(ic(on?"eye-off":"eye",16))}},ic("eye",16));extra.push(eye)}
  if(f.generate)extra.push(h("button",{class:"btn icon",type:"button",title:"Generate a strong password",onclick:async()=>{const r=await api("vault/generate",{length:20});if(r.ok){inp.value=r.pw;inp.type="text";inp.dispatchEvent(new Event("input"))}}},ic("dice",16)));
  const m=f.meter?meter():null;if(m)watch(inp,m);
  return h("div",{class:"fld"},h("label",{},f.label),extra.length?h("div",{class:"row"},inp,extra):inp,m)});
 const go=async()=>{const v={};for(const k in inputs)v[k]=inputs[k].value;ok.disabled=true;err.textContent="";const r=await submit(v);ok.disabled=false;if(r&&r.ok)close(r);else err.textContent=(r&&r.err)||"That didn't work"};
 const key=e=>{if(e.key==="Escape"){e.stopPropagation();close(null)}else if(e.key==="Enter"&&e.target.tagName==="INPUT"){e.preventDefault();go()}};
 const ok=h("button",{class:"btn "+(danger?"dng fill":"pri"),onclick:go},label);
 const bg=h("div",{class:"sheet-bg",style:tone?`--tone:var(--${tone})`:"",onmousedown:e=>{if(e.target===bg)close(null)}},
  h("div",{class:"sheet wide",role:"dialog","aria-modal":"true"},h("div",{class:"bd"},ic(icon,26)),h("h3",{},title),lede?h("p",{},lede):null,rows,err,
   h("div",{class:"btns row"},h("button",{class:"btn ghost",onclick:()=>close(null)},"Cancel"),ok)));
 document.body.append(bg);document.addEventListener("keydown",key,true);bg.offsetWidth;bg.classList.add("on");const f1=Object.values(inputs)[0];if(f1)setTimeout(()=>f1.focus(),120)})}

async function refresh(force){const s=await api("vault/status");if(!s.ok)return;
 if(force||!S||s.rev!==S.rev||s.state!==S.state){S=s;await draw()}else S=s}
async function draw(){root.textContent="";
 if(S.state==="none")return setup();if(S.state==="locked")return unlockView();
 const r=await api("vault/list");if(!r.ok){S=null;return}LIST=r.entries;NEVER=r.never;manager()}

function setup(){
 const p1=h("input",{class:"inp",type:"password",placeholder:"Master password",autocomplete:"new-password"}),p2=h("input",{class:"inp",type:"password",placeholder:"Repeat it",autocomplete:"new-password"}),m=meter(),err=h("div",{class:"err"});watch(p1,m);
 const go=async()=>{if(p1.value!==p2.value){err.textContent="The two passwords don't match.";return}b.disabled=true;const r=await api("vault/create",{pw:p1.value});b.disabled=false;if(r.ok){toast("Vault created");refresh(true)}else err.textContent=r.err||"Couldn't create the vault"};
 p2.addEventListener("keydown",e=>{if(e.key==="Enter")go()});
 const b=h("button",{class:"btn pri lg",onclick:go},"Create vault");
 root.append(h("div",{class:"card"},h("div",{class:"bd"},ic("key",26)),h("h3",{},"Create your password vault"),h("p",{},"Pick one long master password. It unlocks everything, so make it something you can remember without writing it down."),
  h("div",{class:"fld"},h("label",{},"Master password"),p1),m,h("div",{class:"fld"},h("label",{},"Repeat it"),p2),err,b),
  h("h2",{},"Good to know"),h("div",{class:"group"},
   h("div",{class:"item"},h("div",{class:"grow"},h("div",{class:"t"},"There is no recovery"),h("div",{class:"d"},"Nobody, including Shield, can open the vault without your master password. If you forget it, the vault has to be erased."))),
   h("div",{class:"item"},h("div",{class:"grow"},h("div",{class:"t"},"It protects the file, not a compromised computer"),h("div",{class:"d"},"Passwords are encrypted on disk and hidden from websites. Malware running as you could still read them while the vault is unlocked."))),
   h("div",{class:"item"},h("div",{class:"grow"},h("div",{class:"t"},"Bringing logins from another browser"),h("div",{class:"d"},"After creating the vault you can import the CSV file your old browser exports. Delete that file afterwards, it holds passwords in plain text.")))))}

function unlockView(){
 const pw=h("input",{class:"inp",type:"password",placeholder:"Master password",autocomplete:"current-password"}),err=h("div",{class:"err"},S.wait?`Too many tries. Wait ${S.wait} seconds.`:"");
 const go=async()=>{b.disabled=true;const r=await api("vault/unlock",{pw:pw.value});b.disabled=false;if(r.ok){refresh(true)}else{err.textContent=r.err||"That isn't the master password.";pw.select()}};
 pw.addEventListener("keydown",e=>{if(e.key==="Enter")go()});
 const b=h("button",{class:"btn pri lg",onclick:go},"Unlock");
 root.append(h("div",{class:"card"},h("div",{class:"bd"},ic("lock",26)),h("h3",{},"The vault is locked"),h("p",{},"Enter your master password to see and use your logins."),h("div",{class:"fld"},pw),err,b));setTimeout(()=>pw.focus(),150)}

function manager(){
 const bar=h("div",{class:"toolbar"},
  h("button",{class:"btn pri",onclick:()=>edit(null)},ic("plus",16),"Add login"),
  h("button",{class:"btn",onclick:gen},ic("dice",16),"Generate"),
  h("button",{class:"btn",onclick:checkup},ic("shield-check",16),"Check-up"),
  h("button",{class:"btn",onclick:imp},ic("upload",16),"Import"),
  h("button",{class:"btn",onclick:exp},ic("download",16),"Export"),
  h("button",{class:"btn",onclick:async()=>{await api("vault/lock");refresh(true)}},ic("lock",16),"Lock now"));
 const search=h("div",{class:"find",style:"margin-top:12px"},ic("search",16),h("input",{type:"text",id:"s",placeholder:"Search logins",autocomplete:"off",spellcheck:"false",value:Q,oninput:e=>{Q=e.target.value.trim().toLowerCase();list()}}));
 root.append(bar,search,h("div",{id:"aud"}),h("div",{id:"list",style:"margin-top:10px"}));list();audit();more()}

function audit(){const a=$("#aud");a.textContent="";if(!AUD)return;
 const it=(k,label,ids,hint)=>h("div",{class:"item"},h("span",{class:"row-ic",style:"color:var(--"+(ids?"warn":"ok")+")"},ic(ids?"alert":"check",17)),h("div",{class:"grow"},h("div",{class:"t"},label),h("div",{class:"d"},hint)),
  ids?h("button",{class:"btn",onclick:()=>{ONLY=ONLY===k?null:k;list();audit()}},ONLY===k?"Show all":"Show"):h("span",{class:"chip ok"},"None"));
 a.append(h("h2",{},"Check-up"),h("div",{class:"group"},it("weak",AUD.weak.length?`${AUD.weak.length} weak password${AUD.weak.length>1?"s":""}`:"No weak passwords",AUD.weak.length,"Short or easy to guess. Replace them with generated ones."),
  it("reused",AUD.reused?`${AUD.reused} password${AUD.reused>1?"s are":" is"} reused`:"No reused passwords",AUD.reused,"One leak at one site opens every account that shares the password."),
  it("old",AUD.old.length?`${AUD.old.length} not changed in two years`:"Nothing is very old",AUD.old.length,"Worth refreshing for important accounts.")))}
async function checkup(){const r=await api("vault/audit");if(!r.ok)return;AUD=r;ONLY=null;audit();list()}

function list(){const t=$("#list");t.textContent="";
 const flags=AUD?{weak:new Set(AUD.weak),old:new Set(AUD.old),reused:new Set(AUD.reusedIds)}:null;
 let rows=LIST.filter(e=>!Q||(e.host+" "+e.username+" "+e.title).toLowerCase().includes(Q));if(ONLY&&flags)rows=rows.filter(e=>flags[ONLY].has(e.id));
 if(!rows.length){t.append(h("div",{class:"group"},h("div",{class:"empty"},LIST.length?"No matches.":"No saved logins yet. Add one, import a file, or sign in to a site and choose Save when Shield asks.")));return}
 const by={};rows.forEach(e=>(by[e.host]=by[e.host]||[]).push(e));
 const g=h("div",{class:"group"});Object.keys(by).sort().forEach(hn=>by[hn].forEach(e=>g.append(row(e))));t.append(g)}

function row(e){
 const pwv=h("span",{class:"pwv",style:"display:none;margin-top:4px"});let tm=0;
 const chips=[];if(e.weak)chips.push(h("span",{class:"chip warn"},"Weak"));if(e.reused)chips.push(h("span",{class:"chip warn"},"Reused"));
 const bt=(icon,title,fn)=>h("button",{class:"btn icon ghost",title,onclick:fn},ic(icon,16));
 const eye=bt("eye","Show password",async()=>{if(pwv.style.display!=="none"){pwv.style.display="none";clearTimeout(tm);return}
  const r=await api("vault/reveal",{id:e.id});if(!r.ok){toast(r.err||"Couldn't show it");return}pwv.textContent=r.pw;pwv.style.display="inline-block";clearTimeout(tm);tm=setTimeout(()=>{pwv.style.display="none";pwv.textContent=""},10000)});
 return h("div",{class:"item"},h("span",{class:"fav"},e.icon?h("img",{src:e.icon,alt:""}):(e.host[0]||"?").toUpperCase()),
  h("div",{class:"grow"},h("div",{class:"t"},e.host),h("span",{class:"sub"},e.username||"No username"),pwv),chips,
  h("div",{class:"actions"},bt("copy","Copy username",async()=>{const r=await api("vault/copy",{id:e.id,what:"user"});toast(r.ok?"Username copied":(r.err||"Couldn't copy"))}),
   bt("key","Copy password",async()=>{const r=await api("vault/copy",{id:e.id,what:"pass"});toast(r.ok?"Password copied. It leaves the clipboard in 30 seconds.":(r.err||"Couldn't copy"))}),
   eye,bt("edit","Edit",()=>edit(e)),
   bt("trash","Delete",async()=>{const a=await sheet({icon:"trash",tone:"bad",title:"Delete this login?",body:`${e.username||"The login"} for ${e.host} will be removed from the vault.`,actions:[{label:"Delete",kind:"dng fill",value:"ok"},{label:"Cancel",kind:"ghost",value:null}]});
    if(a!=="ok")return;await api("vault/delete",{id:e.id});toast("Deleted");refresh(true)})))}

async function edit(e){let pw="";if(e){const r=await api("vault/reveal",{id:e.id});if(!r.ok){toast(r.err||"Couldn't open it");return}pw=r.pw}
 const r=await modal({title:e?"Edit login":"Add a login",lede:e?"":"Shield will offer this login only on this exact website.",label:e?"Save changes":"Add login",
  fields:[{key:"url",label:"Website",value:e?e.origin:"",placeholder:"https://example.com"},{key:"user",label:"Username or email",value:e?e.username:""},{key:"pw",label:"Password",type:"password",value:pw,generate:true,meter:true}],
  submit:v=>api("vault/save",{id:e?e.id:"",url:v.url,user:v.user,pw:v.pw})});
 if(r){toast(e?"Saved":"Login added");refresh(true)}}

async function gen(){for(;;){const r=await api("vault/generate",{length:20});if(!r.ok)return;
  const a=await sheet({icon:"dice",title:"A new password",body:r.pw,actions:[{label:"Copy it",kind:"pri",value:"copy"},{label:"Another",kind:"",value:"again"},{label:"Close",kind:"ghost",value:null}]});
  if(a==="copy"){await api("vault/copytext",{text:r.pw});toast("Copied. It leaves the clipboard in 30 seconds.");return}if(a!=="again")return}}
async function imp(){const r=await api("vault/import");if(r.cancelled)return;if(!r.ok){toast(r.err||"Couldn't import that file");return}
 toast(`Added ${r.added}, skipped ${r.skipped}. Delete the CSV file now: it holds passwords in plain text.`);refresh(true)}
async function exp(){const r=await modal({icon:"download",tone:"warn",title:"Export your passwords",lede:"The file is NOT encrypted: anyone who gets it can read every password. Confirm with your master password.",label:"Choose where to save",
  fields:[{key:"pw",label:"Master password",type:"password"}],submit:v=>api("vault/export",{pw:v.pw})});
 if(r)toast(r.cancelled?"Export cancelled":"Saved. Delete the file as soon as you've used it.")}

function more(){
 const never=NEVER.length?NEVER.map(hn=>h("div",{class:"item"},h("div",{class:"grow mono",style:"color:var(--text)"},hn),h("button",{class:"btn dng ghost",onclick:async()=>{await api("vault/never/del",{host:hn});refresh(true)}},"Remove"))):[h("div",{class:"empty"},"You haven't told Shield to skip any site.")];
 const sel=(k,label,desc)=>null;
 root.append(h("h2",{},"Master password"),h("div",{class:"group"},
   h("div",{class:"item"},h("div",{class:"grow"},h("div",{class:"t"},"Change master password"),h("div",{class:"d"},"Your logins are re-protected with the new password straight away.")),
    h("button",{class:"btn",onclick:async()=>{const r=await modal({title:"Change master password",label:"Change it",fields:[{key:"old",label:"Current master password",type:"password"},{key:"n1",label:"New master password",type:"password",meter:true},{key:"n2",label:"Repeat the new one",type:"password"}],
      submit:v=>v.n1!==v.n2?{ok:false,err:"The new passwords don't match."}:api("vault/change",{old:v.old,pw:v.n1})});if(r)toast("Master password changed")}},"Change")),
   h("div",{class:"item"},h("div",{class:"grow"},h("div",{class:"t"},"Erase the vault"),h("div",{class:"d"},"Deletes every saved login and the vault file. This can't be undone.")),
    h("button",{class:"btn dng",onclick:async()=>{const r=await modal({icon:"trash",tone:"bad",title:"Erase the vault?",lede:"Every saved login will be deleted for good. Confirm with your master password.",label:"Erase everything",danger:true,fields:[{key:"pw",label:"Master password",type:"password"}],
      submit:v=>api("vault/wipe",{pw:v.pw})});if(r){toast("Vault erased");refresh(true)}}},"Erase"))),
  h("h2",{},"Sites that are never saved"),h("div",{class:"group"},never));}
refresh(true);setInterval(()=>refresh(false),2000);
"""
    return shell(ctx, "Passwords", body, script, nav="passwords")


PAGES = {"newtab": page_newtab, "settings": page_settings, "security": page_security, "passwords": page_passwords,
         "downloads": page_downloads, "history": page_history, "bookmarks": page_bookmarks,
         "warning": page_warning}


# --------------------------------------------------------------------------
# JSON API used by the internal pages
# --------------------------------------------------------------------------
def handle_api(ctx, path, q):
    if not secrets.compare_digest(str(q.get("t", "")).encode("utf-8", "replace"), ctx.token.encode("ascii")):
        return {"ok": False, "err": "bad token"}
    c, app = ctx.cfg, ctx.app
    if path == "events":
        return ctx.events.snapshot()
    if path == "set":
        key = q.get("k", "")
        ok = c.set(key, q.get("v", ""))
        if ok:
            app.on_setting(key)
        return {"ok": ok, "theme": app.resolved_theme(),
                "note": "Saved. Restart Shield to apply." if key in ("persistent_sessions", "hardened_mode") else ""}
    if path == "site/add":
        return {"ok": c.add_rule(q.get("host", ""), q.get("rule", ""))}
    if path == "site/del":
        c.del_rule(q.get("host", ""), q.get("rule", ""))
        return {"ok": True}
    if path == "blocklist":
        c.set_blocklist(q.get("text", ""))
        return {"ok": True}
    if path == "proxy/bridges":
        n, bad = c.set_bridges(q.get("text", ""))
        return {"ok": True, "count": n, "bad": bad}
    if path == "clear":
        app.clear_data(q.get("what", ""))
        return {"ok": True}
    if path == "allow":
        host = q.get("host", "")
        if q.get("kind") == "nohttps":
            ctx.guard.http_ok.add(host)
        else:
            ctx.guard.allowed.add((q.get("kind", ""), site_of(host)))
        return {"ok": True}
    if path == "bookmark/del":
        ctx.store.del_bookmark(q.get("url", ""))
        return {"ok": True}
    if path == "history/del":
        ctx.store.del_history(int(q.get("id", 0) or 0))
        return {"ok": True}
    if path.startswith("vault/"):
        return app.vault_api(path[6:], q)
    if path == "list/set":
        ok = c.set_list(q.get("id", ""), q.get("on") == "1")
        if ok:
            app.lists_changed()
        return {"ok": ok}
    if path == "lists":
        return {"ok": True, **app.list_status()}
    if path == "lists/update":
        return app.lists_update(force=True)
    if path == "update/state":
        return {"ok": True, **app.update_state()}
    if path == "update/check":
        return app.update_check()
    if path == "update/download":
        return app.update_download()
    if path == "engines":
        return {"ok": True, "engines": app.engine_state()}
    if path == "engine/update":
        return app.engine_update(q.get("key", ""))
    if path == "vt/key":
        ok = set_vt_key(q.get("key", ""))
        return {"ok": ok}
    if path == "downloads":
        return {"ok": True, "downloads": app.download_list()}
    if path.startswith("download/") or path.startswith("vt/"):
        try:
            did = int(q.get("id", 0))
        except ValueError:
            return {"ok": False}
        action = path.split("/", 1)[1]
        if path.startswith("vt/"):
            if action == "scan":
                return app.vt_start(did, q.get("upload") == "1")
            if action == "cancel":
                app.vt_cancel(did)
                return {"ok": True}
        elif action == "release":
            ok, err = app.release_download(did, q.get("confirm") == "1")
            return {"ok": ok, "err": err}
        elif action == "delete":
            app.delete_download(did)
            return {"ok": True}
        elif action == "forget":
            app.forget_download(did)
            return {"ok": True}
        elif action == "folder":
            app.open_download_folder(did)
            return {"ok": True}
    return {"ok": False, "err": "unknown"}


class SchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx

    @staticmethod
    def _harden(job, mime):
        """Response headers for internal pages: never cached, never sniffed, never framed, no referrer."""
        try:
            from PyQt6.QtCore import QByteArray
            h = {b"Cache-Control": b"no-store", b"X-Content-Type-Options": b"nosniff", b"Referrer-Policy": b"no-referrer"}
            if mime == b"text/html":
                h[b"X-Frame-Options"] = b"DENY"
            job.setAdditionalResponseHeaders({QByteArray(k): QByteArray(v) for k, v in h.items()})
        except Exception:
            pass          # older Qt without this call: the page-level CSP still applies

    def requestStarted(self, job):
        Err = QWebEngineUrlRequestJob.Error
        try:
            init = job.initiator()
            # Only the browser itself (no initiator) or shield:// pages may talk to shield://.
            if init.isValid() and not init.isEmpty() and init.scheme() != "shield":
                job.fail(Err.RequestDenied)
                return
            url = job.requestUrl()
            q = dict(QUrlQuery(url).queryItems(QUrl.ComponentFormattingOption.FullyDecoded))
            path = url.path()
            if path.startswith("/api/"):
                data = json.dumps(handle_api(self.ctx, path[5:], q)).encode()
                mime = b"application/json"
            else:
                page = PAGES.get(url.host())
                if not page:
                    job.fail(Err.UrlNotFound)
                    return
                data = page(self.ctx, q).encode("utf-8")
                mime = b"text/html"
            buf = QBuffer(job)
            buf.setData(data)
            buf.open(QIODevice.OpenModeFlag.ReadOnly)
            self._harden(job, mime)
            job.reply(mime, buf)
        except Exception:
            job.fail(Err.RequestFailed)
