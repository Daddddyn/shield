SHIELD SOUNDS
=============
These sounds are PART OF THE APP. Users cannot add, replace or edit them: there is no per-user sounds folder.

HOW TO CHANGE THEM (developer)
1. Put your audio files in this folder (next to shield.py).
2. Run:   python tools/pack_sounds.py
   That writes shield_sounds_data.py, which holds the audio inside the app's code.
3. Build as usual. PyInstaller finds shield_sounds_data.py by itself: no --add-data needed.
   Re-run step 2 whenever a file here changes.
(While developing, if you skip step 2, Shield plays this folder directly. Never ship that way.)

FILE NAME          PLAYS WHEN                               IF MISSING
click.wav          any button is pressed                    silent
tab_select.wav     you switch to a tab                      click
tab_new.wav        a new tab opens                          tab_select, then click
tab_close.wav      a tab closes                             click
toggle.wav         private connection on/off                click
star.wav           you bookmark a page                      click
theme.wav          dark <-> light                           toggle, then click
sheet.wav          a dialog opens                           silent
unlock.wav         the vault unlocks (Face ID moment)       success
error.wav          wrong master password, connection fail   silent
success.wav        something finished well                  silent
download.wav       a download lands                         success
connect.wav        private connection established           success
scroll.wav         ONE short tick, every ~72 px scrolled    silent
scroll_loop.wav    a continuous bed that swells with        silent
                   scroll speed (use instead of, or with,
                   scroll.wav)

TIPS
* Easiest start: just click.wav and scroll.wav. Everything else falls back to click.
* VARIATIONS: click.wav, click_2.wav, click_3.wav ... one is picked at random (never the same twice in a row).
* FORMAT: .wav is instant. .mp3/.ogg/.flac/.m4a/.opus also work but start a few tens of ms late. Use .wav for clicks.
* SIZE: the audio is stored inside the app, so keep clips short (30-150 ms for clicks and ticks; scroll_loop 0.5-2 s, seamless).
* Users only get the on/off switch, volume and scroll-sound switch (Settings > Motion and sound).
