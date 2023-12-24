import os
import platform
import plistlib
import shutil
import subprocess
import sys
import warnings
import zipfile

import lief

app_resource_dir = None
app_bundle_executable = None
app_version = None
hooking_library = None
inject_dir_name = None


def cleanup_and_exit():
    # Check if directory exists and remove it
    if os.path.exists("Payload"):
        shutil.rmtree("Payload")
    # Check if files exist and remove them
    for file_name in ["ent.xml", "temp.zip"]:
        if os.path.isfile(file_name):
            os.remove(file_name)
    sys.exit()


def create_dir_in_zip(target_zip: str, dir_name_to_make: str):
    # Open the existing zip file in append mode
    with zipfile.ZipFile(target_zip, 'a') as zip_ref:
        # Create a ZipInfo object with the directory name and the correct external attributes
        dir_info = zipfile.ZipInfo(dir_name_to_make)
        dir_info.external_attr = 0o755 << 16  # Set proper directory attributes
        # Add the directory to the existing zip file
        zip_ref.writestr(dir_name_to_make, '')
        print(f"[*] Created {dir_name_to_make} in a {target_zip}")


def add_directory_to_zip(zip_ref, dir_path, target_dir=""):
    source_dir_name = os.path.basename(dir_path)
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            arc_path = os.path.join(target_dir, source_dir_name, os.path.relpath(file_path, dir_path))
            zip_ref.write(file_path, arcname=arc_path)


def add_file_to_zip(target_zip: str, file_to_insert: str, target_dir: str):
    # Open the existing zip file in append mode
    with zipfile.ZipFile(target_zip, 'a') as zip_ref:
        if "CydiaSubstrate" in file_to_insert:
            add_directory_to_zip(zip_ref, file_to_insert, target_dir)
        elif "CS" in file_to_insert:
            add_directory_to_zip(zip_ref, file_to_insert, target_dir)
        else:
            arcname = os.path.join(target_dir, os.path.basename(file_to_insert))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                zip_ref.write(file_to_insert, arcname=arcname)
            print(f"[*] {file_to_insert} added into {target_zip}")
            zip_ref.close()


def read_plist(target_zip: str) -> None:
    with zipfile.ZipFile(target_zip, 'r') as zip_ref:
        # Iterate through the target files
        for file in zip_ref.namelist():
            if ".app/Info.plist" in file:
                global app_resource_dir
                app_resource_dir, _, _ = file.rpartition('/')
                zip_ref.extract(file)
                # Read the plist file and load its contents into a dictionary
                with open(file, 'rb') as File:
                    plist_data = plistlib.load(File)
                    # Access a specific value using the key
                    keys = ["CFBundleExecutable", "CFBundleShortVersionString"]
                    global app_bundle_executable, app_version
                    app_bundle_executable = plist_data.get(keys[0])
                    app_version = plist_data.get(keys[1])


def modify_plist(target_plist: str, UISupportedDevices: bool, MinimumOSVersion: bool) -> None:
    if (UISupportedDevices is True) or (MinimumOSVersion is True):
        with open(target_plist, 'rb') as File:
            plist_data = plistlib.load(File)

        if UISupportedDevices is True:
            key = "UISupportedDevices"
            if key in plist_data:
                del plist_data[key]
                print(f"[*] {target_plist} key: {key} is removed successfully")

        if MinimumOSVersion is True:
            key = "MinimumOSVersion"
            if key in plist_data:
                origin_version = plist_data[key]
                plist_data[key] = '12.0'
                print(f"[*] {target_plist} key: {key} is changed to 12.0 from {origin_version} successfully")

        with open(target_plist, 'wb') as File:
            plistlib.dump(plist_data, File)


def remove_file_and_rezip(zip_file_path, file_to_remove):
    # Create a temporary directory
    temp_dir = 'temp_unzipped'
    os.makedirs(temp_dir, exist_ok=True)

    # Unzip the archive
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # Remove the specified file
    file_path = os.path.join(temp_dir, file_to_remove)
    if os.path.isdir(file_path):
        shutil.rmtree(file_path)
    elif os.path.exists(file_path):
        os.remove(file_path)

    # Create a new zip file
    new_zip_path = zip_file_path.replace('.zip', '_modified.zip')
    with zipfile.ZipFile(new_zip_path, 'w') as zip_ref:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                zip_ref.write(file_path, os.path.relpath(file_path, temp_dir))

    # Clean up: remove the temporary directory
    shutil.rmtree(temp_dir)
    os.remove(zip_file_path)
    os.rename(new_zip_path, zip_file_path)
    os.chmod(zip_file_path, 0o644)


def unzip(target_zip: str, target_file: str) -> None:
    # Open the zip file using 'with' statement
    with zipfile.ZipFile(target_zip, 'r') as zip_ref:
        # Check if the file exists in the zip archive
        for file in zip_ref.namelist():
            if target_file in file:
                # Extract the specific file to the current working directory
                zip_ref.extract(file)
        zip_ref.close()


def ldid_work(target: str, what_work: str) -> None:
    command = None
    log = None
    ldid_bin = None
    if platform.system() == "Darwin":
        ldid_bin = "bin/ldid_macosx_arm64" if platform.machine() == "arm64" else "bin/ldid_macosx_x86_64"
    elif platform.system() == "Windows":
        ldid_bin = "bin\ldid_w64_x86_64.exe"
    elif platform.system() == "Linux":
        ldid_bin = "bin/ldid_linux_aarch64" if platform.machine() == "arm64" else "bin/ldid_linux_x86_64"

    if what_work == 'save':
        log = ['Saved entitlements', 'Failed to save entitlements']
        if platform.system() == "Windows":
            target = target.replace('/', '\\')
        command = f'{ldid_bin} -e \"{target}\" > ent.xml'
    elif what_work == 'remove':
        log = ['Removed codesign', 'Failed to remove codesign']
        if platform.system() == "Windows":
            target = target.replace('/', '\\')
        command = f'{ldid_bin} -r \"{target}\"'
    elif what_work == 'restore':
        log = ['Restored entitlements', 'Failed to restore entitlements']
        if platform.system() == "Windows":
            target = target.replace('/', '\\')
            command = f'{ldid_bin} -S.\ent.xml \"{target}\"'
        else:
            command = f'{ldid_bin} -S./ent.xml \"{target}\"'
    # Execute the command and capture the output
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    # Check the return code to see if the command executed successfully
    if result.returncode == 0:
        print(f"[*] {target.rpartition('/')[-1]} {log[0]} successfully")
    else:
        print(f"[!] {log[1]} for {target.rpartition('/')[-1]}")
        cleanup_and_exit()
        return


def insert_dylib(target_executable: str, target_tweak: str):
    binary = lief.parse(target_executable)
    if not lief.is_macho(target_executable):
        print(f"[!] {target_executable} is not Mach-O file")
        cleanup_and_exit()
        return

    target_tweak = target_tweak.rpartition('\\')[-1] if platform.system() == "Windows" else \
    target_tweak.rpartition('/')[-1]
    library_to_add = f"@executable_path/{inject_dir_name}/{target_tweak}"
    result = binary.add_library(library_to_add)
    if result is not None:
        binary.write(target_executable)
        print(f"[*] {target_tweak} inserted to {target_executable} successfully")
        return
    else:
        print(f"[!] Couldn't insert dylib into {target_executable}")
        cleanup_and_exit()
        return


def fix_tweak(target_tweak: str):
    binary = lief.parse(target_tweak)

    found_id_dylib = False
    found_load_dylib = False
    # Find the LC_ID_DYLIB command and modify it
    for command_id_dylib in binary.commands:
        if isinstance(command_id_dylib,
                      lief.MachO.DylibCommand) and command_id_dylib.command == lief.MachO.LOAD_COMMAND_TYPES.ID_DYLIB:
            old_id_dylib = command_id_dylib.name
            new_id_dylib = f"@executable_path/{inject_dir_name}/{target_tweak.rpartition('/')[-1]}"
            size_to_pad = len(old_id_dylib) - len(new_id_dylib)
            if size_to_pad >= 0:
                pad_str = ''.join(["\x00"] * size_to_pad)
            else:
                print("[!] Original LC_ID_DYLIB is too short")
                print(f"[!] Couldn't fix LC_ID_DYLIB of {target_tweak.rpartition('/')[-1]}")
                cleanup_and_exit()
                return
            command_id_dylib.name = f"{new_id_dylib}{pad_str}"
            found_id_dylib = True
            break
    # Find the LC_LOAD_DYLIB command and modify it
    for command_load_dylib in binary.commands:
        if isinstance(command_load_dylib,
                      lief.MachO.DylibCommand) and command_load_dylib.command == lief.MachO.LOAD_COMMAND_TYPES.LOAD_DYLIB:
            if "substrate" in command_load_dylib.name.lower():
                print(f"[*] Found command {command_load_dylib.name} to fix")
                old_load_dylib = command_load_dylib.name
                new_load_dylib = f"@executable_path/{inject_dir_name}/{hooking_library}"
                size_to_pad = len(old_load_dylib) - len(new_load_dylib)
                if size_to_pad >= 0:
                    pad_str = ''.join(["\x00"] * size_to_pad)
                else:
                    # if original LC_LOAD_DYLIB is "@rpath/CydiaSubstrate.framework/CydiaSubstrate",
                    # need to make the new_load_dylib length shorter than the origin one
                    if "CydiaSubstrate" in hooking_library:
                        old_inject_lib = "lib/CydiaSubstrate"
                        new_inject_lib = "lib/CS"
                        shutil.copytree(old_inject_lib, new_inject_lib)
                        remove_file_and_rezip("temp.zip", f"{app_resource_dir}/{inject_dir_name}/{old_inject_lib.rpartition('/')[-1]}/")
                        add_file_to_zip("temp.zip", new_inject_lib, f"{app_resource_dir}/{inject_dir_name}/")

                        new_hooking_library = "CS/CydiaSubstrate"
                        new_load_dylib = f"@executable_path/{inject_dir_name}/{new_hooking_library}"
                        size_to_pad = len(old_load_dylib) - len(new_load_dylib)
                        pad_str = ''.join(["\x00"] * size_to_pad)

                        shutil.rmtree(new_inject_lib)
                    else:
                        print("[!] Original LC_LOAD_DYLIB is too short")
                        print(f"[!] Couldn't fix LC_LOAD_DYLIB of {target_tweak.rpartition('/')[-1]}")
                        cleanup_and_exit()
                        return
                command_load_dylib.name = f"{new_load_dylib}{pad_str}"
                found_load_dylib = True
                break

    if not found_id_dylib:
        print("[!] LC_ID_DYLIB command not found.")
        print(f"[!] Couldn't fix LC_ID_DYLIB of {target_tweak.rpartition('/')[-1]}")
        cleanup_and_exit()
        return
    elif not found_load_dylib:
        print("[!] Failed to find a substrate dylib to change")
        print(f"[!] Couldn't fix LC_LOAD_DYLIB of {target_tweak.rpartition('/')[-1]}")
        cleanup_and_exit()
        return
    else:
        # Save the modified binary
        binary.write(target_tweak)
        print(f"[*] {target_tweak.rpartition('/')[-1]} LC_ID_DYLIB, LC_LOAD_DYLIB has been updated.")
        print(f"[*] {target_tweak.rpartition('/')[-1]} fixed successfully")


if __name__ == '__main__':
    # Get user input for the target IPA
    while True:
        targetZip = input("Target decrypted ipa (full or relative path): ").strip().replace('"', '').replace('\'', '')
        if os.path.exists(targetZip):
            break
        else:
            print("[!] Specified file is not exists. Input again\n")

    # get user input of the target tweak
    while True:
        targetTweaks = [input("Target tweak dylib to inject (full or relative path): ").strip().replace('"', '').replace('\'', '')]
        if os.path.exists(targetTweaks[0]):
            while True:
                another_tweak_ans = input("Another? [Y/n]: ").lower().strip()
                if another_tweak_ans == "y" or another_tweak_ans == "yes":
                    another_tweak_path = input("Target tweak dylib to inject (full or relative path): ").strip().replace('"', '').replace('\'', '')
                    if os.path.exists(another_tweak_path):
                        targetTweaks.append(another_tweak_path)
                    else:
                        print("[!] Specified tweak is not exists\n")
                else:
                    break
            break
        else:
            print("[!] Specified tweak is not exists\n")

    # Specify to inject directory name where we push our tweak and hooking library
    inject_dir_name = "mlinject"

    # select hooking library prompt
    hooking_lib = ["Ellekit", "CydiaSubstrate"]
    for i in range(len(hooking_lib)):
        print(f"[{i + 1}]. {hooking_lib[i]}")

    while True:
        num = input("\nChoose a hooking library to use: ")
        if num.isdigit() and 1 <= int(num) <= 2:
            inject_lib = hooking_lib[int(num) - 1]
            if inject_lib == "CydiaSubstrate":
                inject_lib = "lib/CydiaSubstrate"
                hooking_library = "CydiaSubstrate/CydiaSubstrate"
            elif inject_lib == "Ellekit":
                inject_lib = "lib/libellekit.dylib"
                hooking_library = "libellekit.dylib"
            break
        else:
            print("Wrong hooking library number. Choose again")

    while True:
        UISupportedDevices_ans = input("\nRemove UISupportedDevices? [Y/n]: ")
        UISupportedDevices_ans = UISupportedDevices_ans.lower().strip()
        if UISupportedDevices_ans == "y" or UISupportedDevices_ans == "yes":
            UISupportedDevices_ans = True
        else:
            UISupportedDevices_ans = False
        break

    while True:
        MinimumOSVersion_ans = input("\nChange MinimumOSVersion to 12.0? [Y/n]: ")
        MinimumOSVersion_ans = MinimumOSVersion_ans.lower().strip()
        if MinimumOSVersion_ans == "y" or MinimumOSVersion_ans == "yes":
            MinimumOSVersion_ans = True
        else:
            MinimumOSVersion_ans = False
        break

    # notify dylib injection start
    print("")
    for targetTweak in targetTweaks:
        print(f"[*] {targetTweak.rpartition('/')[-1]} injection start")
        print("")
    # create temp zip file
    temp_zip_file = "temp.zip"
    if shutil.copy2(targetZip, temp_zip_file) is not None:
        print(f"[*] Temporarily zip file \"{temp_zip_file}\" created")
        print("")
    else:
        print("[!] Couldn't create temporarily zip file")

    # read Info.plist to get some infos
    read_plist(temp_zip_file)

    # remove UISupportedDevices, change MinimumOSVersion if we want
    info_plist_file = f"{app_resource_dir}/Info.plist"
    unzip(temp_zip_file, info_plist_file)
    modify_plist(info_plist_file, UISupportedDevices_ans, MinimumOSVersion_ans)
    remove_file_and_rezip(temp_zip_file, info_plist_file)
    add_file_to_zip(temp_zip_file, info_plist_file, f"{app_resource_dir}")
    print("")

    # work for app's main executable
    app_main_executable = f"{app_resource_dir}/{app_bundle_executable}"

    unzip(temp_zip_file, app_main_executable)
    # save entitlements of the app's main executable
    ldid_work(app_main_executable, "save")
    # remove code signature of the app's main executable
    ldid_work(app_main_executable, "remove")
    print("")

    # Insert dylib into the app's main executable and add the file to the zip
    for targetTweak in targetTweaks:
        insert_dylib(app_main_executable, targetTweak)
    print("")

    # restore entitlements of the app's main executable
    ldid_work(app_main_executable, "restore")
    if platform.system() == "Windows":
        remove_file_and_rezip(temp_zip_file, app_main_executable)
    add_file_to_zip(temp_zip_file, app_main_executable, f"{app_resource_dir}")
    print("")

    # create hooking lib dir in the zip file
    hooking_lib_dir_to_make = f"{app_resource_dir}/{inject_dir_name}/"
    create_dir_in_zip(temp_zip_file, hooking_lib_dir_to_make)
    # add hooking library in the zip file
    add_file_to_zip(temp_zip_file, inject_lib, hooking_lib_dir_to_make)
    # add tweak dylib in the zip file
    for targetTweak in targetTweaks:
        add_file_to_zip(temp_zip_file, targetTweak, hooking_lib_dir_to_make)
    # unzip it
    unzip(temp_zip_file, f"{hooking_lib_dir_to_make}")
    print("")

    for targetTweak in targetTweaks:
        if platform.system() == "Windows":
            targetTweak = targetTweak.rpartition('\\')[-1]
        else:
            targetTweak = targetTweak.rpartition('/')[-1]
        # remove code signature of the tweak dylib
        ldid_work(f"{hooking_lib_dir_to_make}{targetTweak}", "remove")
        # fix LC_ID_DYLIB, LO_LOAD_DYLIB of the tweak dylib
        fix_tweak(f"{hooking_lib_dir_to_make}{targetTweak}")
        # remove the tweak dylib before adding the fixed tweak dylib in the zip file
        if platform.system() == "Windows":
            remove_file_and_rezip(temp_zip_file, f"{hooking_lib_dir_to_make}{targetTweak}")
        # add the fixed tweak in the zip file
        add_file_to_zip(temp_zip_file, f"{hooking_lib_dir_to_make}{targetTweak}", hooking_lib_dir_to_make)
    print("")

    out = f"{app_bundle_executable}_v{app_version}_injected.ipa"
    shutil.move(temp_zip_file, out)
    print(f"[*] Injection Done! {out}")

    # clean up
    cleanup_and_exit()
