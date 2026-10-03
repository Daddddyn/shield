# Shield 2.2

A zero-bloat, security-first browser on the Chromium engine (PyQt6-WebEngine).

    pip install -r requirements.txt
    python shield.py [https://address ...]

## What's new in 2.2

**Blocking**
- Real filter-list engine (`shield_filters.py`): standard ad/tracker lists, indexed so a request costs well under a
  millisecond. Network rules, exceptions, `$third-party`, `$domain=`, `$important`, `$badfilter`, hosts files, and
  page-cleanup (element hiding) rules. Rules it cannot honour exactly are skipped, never half-applied.
- Lists are downloaded over HTTPS only, checked, and swapped in atomically. Settings > Protection lists turns each on
  or off. Names in the UI describe what a list does; no third-party brand is shown.
- Harmful-site warnings: live phishing and malware feeds plus a scam list, matched on this computer.
- Link cleaning: tracking parameters (`utm_*`, `fbclid`, ...) and click-counting redirects are removed from links.
- Per-site switch: lock icon > "Turn off ad and tracker blocking here".

**Fingerprint protection v2** (`shield_scripts.py`): noise is seeded per site, so sites cannot compare notes. Canvas,
WebGL read-back and audio are covered, patched functions report themselves as native, and Standard/Strict levels.

**Passwords** (`shield_vault.py`, `shield_autofill.py`): encrypted local vault (scrypt + AES-256-GCM), generator,
strength meter, check-up (weak / reused / old), CSV import and export, auto-lock, clipboard auto-clear. Logins fill only
when you pick one from the key button, only on the exact origin, only over HTTPS, never in iframes.

**Browser basics**: restore last session, pinned tabs, tab mute, close tabs to the right, Ctrl+1..9, print, save as PDF,
view source, developer tools (F12), command-line addresses, one running copy (links from other apps open as tabs),
autoplay off, clear data on exit.

**Updates** (`shield_update.py`): once a day, checks whether a newer PyQt6-WebEngine exists (the Chromium security
patches live there). Optional signed self-update notifier for Shield itself, see below.

**Secrets**: the VirusTotal key is encrypted with Windows DPAPI.

## Tests

    python -m unittest discover -s tests -t .

Covers the filter engine, vault, scripts (run under Node if installed), updater signatures, the request interceptor and
navigation guard, and every internal page. PyQt6 is faked for those (`tests/qt_stub.py`), so they run anywhere.

## Signed updates for Shield itself (optional)

    python shield_update.py keygen                 # prints the public key; keep shield-update.key secret
    # put the public key in UPDATE_PUBKEY and your manifest address in UPDATE_URL (shield_update.py)
    python shield_update.py sign manifest.json     # writes manifest.json.sig; upload both files

Until both are filled in the Shield row under Settings > Updates is hidden. Sign the installer itself with your
code-signing certificate as well, otherwise Windows SmartScreen will warn.

## Default browser on Windows

    python tools/register_windows.py

Adds Shield to Default apps (current user only). `--remove` undoes it.

## Not included on purpose

Extensions, sync, accounts, telemetry, and any VPN or Tor routing.
