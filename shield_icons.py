"""
shield_icons.py: one icon set for the whole browser (native toolbar and internal pages).

Every icon sits on a 24x24 grid, drawn with a 1.6 px round stroke so they all
carry the same weight. Names ending in "-fill" are solid. No Qt in this file.
"""

_DOT = '<circle cx="{x}" cy="{y}" r="{r}" fill="currentColor" stroke="none"/>'

ICONS = {
    # navigation
    "back": '<path d="M14.5 5.5L8 12l6.5 6.5"/>',
    "forward": '<path d="M9.5 5.5L16 12l-6.5 6.5"/>',
    "reload": '<path d="M20 12a8 8 0 1 1-2.34-5.66L20 8.7"/><path d="M20 4v4.7h-4.7"/>',
    "close": '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
    "plus": '<path d="M12 5.5v13M5.5 12h13"/>',
    "home": '<path d="M4.5 11.2L12 4.5l7.5 6.7"/><path d="M6.5 9.8V19a1 1 0 0 0 1 1H10v-5h4v5h2.5a1 1 0 0 0 1-1V9.8"/>',
    "search": '<circle cx="10.8" cy="10.8" r="6"/><path d="M15.3 15.3l4.2 4.2"/>',
    "more": _DOT.format(x=5.5, y=12, r=1.5) + _DOT.format(x=12, y=12, r=1.5) + _DOT.format(x=18.5, y=12, r=1.5),
    "chevron-right": '<path d="M9.5 6l6 6-6 6"/>',
    "chevron-up": '<path d="M6 14.5l6-6 6 6"/>',
    "chevron-down": '<path d="M6 9.5l6 6 6-6"/>',
    "arrow-right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "check": '<path d="M5.5 12.5l4.3 4.3 8.7-9"/>',
    # security
    "lock": '<rect x="5.5" y="10.8" width="13" height="9.4" rx="2.4"/><path d="M8.5 10.8V8.2a3.5 3.5 0 0 1 7 0v2.6"/>',
    "lock-open": '<rect x="5.5" y="10.8" width="13" height="9.4" rx="2.4"/><path d="M8.5 10.8V8.2a3.5 3.5 0 0 1 6.8-1.2"/>',
    "shield": '<path d="M12 3.8l7 2.5v5.4c0 4.2-2.9 7.5-7 9-4.1-1.5-7-4.8-7-9V6.3z"/>',
    "shield-check": '<path d="M12 3.8l7 2.5v5.4c0 4.2-2.9 7.5-7 9-4.1-1.5-7-4.8-7-9V6.3z"/><path d="M8.9 12.1l2.2 2.2 4.1-4.3"/>',
    "shield-alert": '<path d="M12 3.8l7 2.5v5.4c0 4.2-2.9 7.5-7 9-4.1-1.5-7-4.8-7-9V6.3z"/><path d="M12 8.6v4"/>' + _DOT.format(x=12, y=15.6, r=0.9),
    "alert": '<path d="M12 4.4L20.8 19.4H3.2z"/><path d="M12 10v4"/>' + _DOT.format(x=12, y=16.6, r=0.9),
    "info": '<circle cx="12" cy="12" r="8.2"/><path d="M12 11.3v5"/>' + _DOT.format(x=12, y=8, r=0.9),
    "key": '<circle cx="8.3" cy="15.7" r="3.5"/><path d="M10.8 13.2L19 5"/><path d="M16.2 7.8l2.4 2.4"/><path d="M13.7 10.3l1.7 1.7"/>',
    "scan": '<path d="M4.5 8V6.2a1.7 1.7 0 0 1 1.7-1.7H8M16 4.5h1.8a1.7 1.7 0 0 1 1.7 1.7V8M19.5 16v1.8a1.7 1.7 0 0 1-1.7 1.7H16M8 19.5H6.2a1.7 1.7 0 0 1-1.7-1.7V16"/><path d="M4.5 12h15"/>',
    # content
    "star": '<path d="M12 4.2l2.3 4.8 5.2.7-3.8 3.7.9 5.2L12 16l-4.6 2.6.9-5.2-3.8-3.7 5.2-.7z"/>',
    "star-fill": '<path d="M12 4.2l2.3 4.8 5.2.7-3.8 3.7.9 5.2L12 16l-4.6 2.6.9-5.2-3.8-3.7 5.2-.7z" fill="currentColor"/>',
    "bookmark": '<path d="M7.2 4.5h9.6a.7.7 0 0 1 .7.7v14.3L12 15.8 6.5 19.5V5.2a.7.7 0 0 1 .7-.7z"/>',
    "clock": '<circle cx="12" cy="12" r="8.2"/><path d="M12 7.6V12l3 1.8"/>',
    "globe": '<circle cx="12" cy="12" r="8.3"/><path d="M3.7 12h16.6"/><path d="M12 3.7c2.3 2.3 3.5 5 3.5 8.3S14.3 18 12 20.3C9.7 18 8.5 15.3 8.5 12S9.7 6 12 3.7z"/>',
    "sliders": '<path d="M4.5 7.5h9M17.5 7.5h2M4.5 16.5h2M10.5 16.5h9"/><circle cx="15.5" cy="7.5" r="2"/><circle cx="8.5" cy="16.5" r="2"/>',
    # files and actions
    "download": '<path d="M12 4.5v10"/><path d="M7.8 10.6l4.2 4.2 4.2-4.2"/><path d="M5.5 19.5h13"/>',
    "upload": '<path d="M12 15.5v-10"/><path d="M7.8 9.4L12 5.2l4.2 4.2"/><path d="M5.5 19.5h13"/>',
    "trash": '<path d="M4.5 7h15"/><path d="M9.5 7V5.2a.7.7 0 0 1 .7-.7h3.6a.7.7 0 0 1 .7.7V7"/><path d="M6.7 7l.7 11.6a1.4 1.4 0 0 0 1.4 1.3h6.4a1.4 1.4 0 0 0 1.4-1.3L17.3 7"/>',
    "folder": '<path d="M4 7.4a1.6 1.6 0 0 1 1.6-1.6h3.7l1.9 2.1h7.2A1.6 1.6 0 0 1 20 9.5v8.1a1.6 1.6 0 0 1-1.6 1.6H5.6A1.6 1.6 0 0 1 4 17.6z"/>',
    "external": '<path d="M13.5 5h5.5v5.5"/><path d="M19 5l-8 8"/><path d="M17.5 14v3.7a1.5 1.5 0 0 1-1.5 1.5H6.3a1.5 1.5 0 0 1-1.5-1.5V8a1.5 1.5 0 0 1 1.5-1.5H10"/>',
    "copy": '<rect x="8.5" y="8.5" width="11" height="11" rx="2"/><path d="M15.5 8.5V6.2a1.7 1.7 0 0 0-1.7-1.7H6.2a1.7 1.7 0 0 0-1.7 1.7v7.6a1.7 1.7 0 0 0 1.7 1.7h2.3"/>',
    "file": '<path d="M7 3.8h6.4l5.1 5.1v10.8A1.5 1.5 0 0 1 17 21.2H7a1.5 1.5 0 0 1-1.5-1.5V5.3A1.5 1.5 0 0 1 7 3.8z"/><path d="M13.2 3.9v5.2h5.2"/>',
    "window": '<rect x="4" y="5" width="16" height="14" rx="2.2"/><path d="M4 9.4h16"/>' + _DOT.format(x=7, y=7.2, r=0.7) + _DOT.format(x=9.4, y=7.2, r=0.7),
    "terminal": '<rect x="4" y="5" width="16" height="14" rx="2.2"/><path d="M7.8 10l2.6 2-2.6 2"/><path d="M12.8 14.4h3.4"/>',
    "archive": '<rect x="4.5" y="5.5" width="15" height="3.8" rx="1"/><path d="M5.8 9.3V18a1.4 1.4 0 0 0 1.4 1.4h9.6a1.4 1.4 0 0 0 1.4-1.4V9.3"/><path d="M10 13h4"/>',
    "eye": '<path d="M2.8 12S6.3 5.8 12 5.8 21.2 12 21.2 12 17.7 18.2 12 18.2 2.8 12 2.8 12z"/><circle cx="12" cy="12" r="2.8"/>',
    "eye-off": '<path d="M9.9 6.1A9.6 9.6 0 0 1 12 5.8c5.7 0 9.2 6.2 9.2 6.2a16 16 0 0 1-3.1 3.7M6.3 7.7A16 16 0 0 0 2.8 12S6.3 18.2 12 18.2a9.7 9.7 0 0 0 4.2-.9"/><path d="M9.9 10a2.8 2.8 0 0 0 4 4"/><path d="M4.5 4.5l15 15"/>',
    "pin": '<path d="M9 4.5h6l-.8 5.2 3.3 3.3v1.5h-11V13l3.3-3.3z"/><path d="M12 14.5V20"/>',
    "volume": '<path d="M5 9.5h3l4-3.5v12l-4-3.5H5z"/><path d="M15.5 9a4 4 0 0 1 0 6"/><path d="M18 6.5a7.5 7.5 0 0 1 0 11"/>',
    "volume-off": '<path d="M5 9.5h3l4-3.5v12l-4-3.5H5z"/><path d="M16 9.5l5 5M21 9.5l-5 5"/>',
    "printer": '<path d="M7 9V4.5h10V9"/><rect x="4.5" y="9" width="15" height="7.5" rx="1.8"/><path d="M7 14h10v5.5H7z"/>',
    "code": '<path d="M9 7l-5 5 5 5M15 7l5 5-5 5"/>',
    "edit": '<path d="M5 19l1-4.2L16.2 4.6a1.7 1.7 0 0 1 2.4 0l.8.8a1.7 1.7 0 0 1 0 2.4L9.2 18z"/><path d="M14.5 6.3l3.2 3.2"/>',
    "dice": '<rect x="4.5" y="4.5" width="15" height="15" rx="3"/>' + _DOT.format(x=8.7, y=8.7, r=1.1) + _DOT.format(x=15.3, y=8.7, r=1.1) + _DOT.format(x=12, y=12, r=1.1) + _DOT.format(x=8.7, y=15.3, r=1.1) + _DOT.format(x=15.3, y=15.3, r=1.1),
    "image": '<rect x="4" y="5" width="16" height="14" rx="2.2"/><circle cx="9" cy="10" r="1.5"/><path d="M5 17l4.5-4.5 3.5 3.5 2.5-2.5 3.5 3.5"/>',
}


def svg(name, size=20, stroke=1.6, cls="", extra=""):
    """Inline SVG markup that inherits the surrounding text colour."""
    body = ICONS[name]
    return (f'<svg class="ic {cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" {extra}>{body}</svg>')


def svg_doc(name, color="#ffffff", stroke=1.6):
    """A standalone SVG document with the colour baked in (for QSvgRenderer, which has no currentColor)."""
    body = ICONS[name].replace("currentColor", color)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')


def sprite():
    """All icons as <symbol>s so pages can reference them with <use> and stay small."""
    out = ['<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0" style="position:absolute" aria-hidden="true">']
    for n, body in ICONS.items():
        out.append(f'<symbol id="i-{n}" viewBox="0 0 24 24">{body}</symbol>')
    out.append("</svg>")
    return "".join(out)
