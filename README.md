# mlinject
A simple python tool for injecting a dylib into an IPA, everyone can understand what's going on behind the scenes<br>
Because this tool simply perform the following steps<br>
1. Save the entitlements of the app's main bundle executable using ldid 
2. Remove the code signature of the app's main bundle executable using ldid
3. Insert tweak dylib into the executable's LC_LOAD_DYLIB
4. Recover the entitlements using ldid
5. Remove the code signature of the tweak dylib using ldid
6. Change LC_ID_DYLIB of the tweak
7. Change LC_LOAD_DYLIB of the tweak with our hooking library
8. Move the modified items(executable, tweak, hooking lib) into the zip

# Usage
Git clone this repo<br>
pip install -r requirements.txt<br>
python main.py<br>
follow the instruction prompts<br>
It will inject CydiaSubstrate or [libellekit.dylib](https://github.com/evelyneee/ellekit) as a hooking library

# Credits
[Azule](https://github.com/Al4ise/Azule)<br>
[ldid](https://github.com/ProcursusTeam/ldid)<br>
[LIEF](https://github.com/lief-project/LIEF)
