# mlinject
A simple python tool for injecting a dylib into an IPA, everyone can understand what's going on behind the scenes<br>
Because this tool simply perform the following steps<br>
1. Save the entitlements of the app's main bundle executable using ldid 
2. Remove the code signature of the app's main bundle executable using ldid
3. Insert tweak dylib into the executable using [insert_dylib](https://github.com/tyilo/insert_dylib)
4. Recover the entitlements using ldid
5. Remove the code signature of the tweak dylib using ldid
6. Change LC_ID_DYLIB of the tweak using install_name_tool
7. Change LC_LOAD_DYLIB of the tweak with our hooking library using install_name_tool
8. Move the modified items(executable, tweak, hooking lib) into the zip

# Prerequisites
* macOS
* ldid, install_name_tool, insert_dylib (somehow, on my Mac everything has already been installed. You can easily install these tools too. Google it)

# Usage
python main.py<br>
follow the instruction prompts<br>
It will inject CydiaSubstrate or [libellekit.dylib](https://github.com/evelyneee/ellekit) as a hooking library, however it seems that libellekit.dylib not working on the jailed device

# Credits
[Azule](https://github.com/Al4ise/Azule)
