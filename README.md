# C4rr07Cr4kR — Console 2.0

Extract the complete ZIP. On Windows, double-click run.bat. On Linux, run
python3 workbench.py. Python 3 and a current browser are required.
The console opens locally. Leave the launcher window open during use.

Paste hashes or select a hash-list file, select the known digest type, and
supply candidate passwords or a UTF-8 wordlist. Start attack runs matching in
a background worker. The console reports actual tested candidates, average
speed, active time, search coverage and verified matches. Pause suspends the
search. Stop retains partial results. Copy and Export save displayed results.

Supported browser recovery formats are raw MD5, SHA-1, SHA-256, SHA-384 and
SHA-512. Use one hash per line. Candidate search is limited to 100,000 entries
per run and wordlist files to 5 MiB. File inspection accepts up to 32 MiB.
Analyze provides format clues. Decode / Ciphers provides encoding, Atbash and
Caesar candidate previews. Format clues and cipher previews need verification.

The bundled Python engine and its CLI remain available for existing workflows.
All graphical launchers open Console 2.0. Use python c4rr07cr4ckr.py --help for
CLI options and install.bat or install.sh for optional engine dependencies.

Validation covered standard digest vectors, real browser sample recovery,
worker pause/stop and partial results. Windows batch launch and GPU cracking
have not been tested on Windows in this environment.
