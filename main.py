import re
import shutil
import sys
import warnings
import zipfile
import plistlib
import subprocess
import os

app_resource_dir = None
app_bundle_executable = None
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
        else:
            arcname = os.path.join(target_dir, os.path.basename(file_to_insert))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                zip_ref.write(file_to_insert, arcname=arcname)
            print(f"[*] {file_to_insert} added into {target_zip}")


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
                    key = "CFBundleExecutable"
                    global app_bundle_executable
                    app_bundle_executable = plist_data.get(key)


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


def unzip(target_zip: str, target_file: str) -> None:
    # Open the zip file using 'with' statement
    with zipfile.ZipFile(target_zip, 'r') as zip_ref:
        # Check if the file exists in the zip archive
        for file in zip_ref.namelist():
            if target_file in file:
                # Extract the specific file to the current working directory
                zip_ref.extract(file)


def ldid_work(target: str, what_work: str) -> None:
    command = None
    log = None
    if what_work == 'save':
        log = ['Saved entitlements', 'Failed to save entitlements']
        # Specify the command you want to run
        command = f'ldid -e {target} > ent.xml'
    elif what_work == 'remove':
        log = ['Removed codesign', 'Failed to remove codesign']
        command = f'ldid -r {target}'
    elif what_work == 'restore':
        log = ['Restored entitlements', 'Failed to restore entitlements']
        command = f'ldid -S./ent.xml {target}'
    # Execute the command and capture the output
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    # Check the return code to see if the command executed successfully
    if result.returncode == 0:
        print(f"[*] {target.rpartition('/')[-1]} {log[0]} successfully")
    else:
        print(f"[*] {log[1]} for {target.rpartition('/')[-1]}")


def insert_dylib(target_executable: str, target_tweak: str):
    # Specify the command you want to run
    command = ["insert_dylib", "--inplace", "--no-strip-codesig", f"@executable_path/{inject_dir_name}/{target_tweak}", target_executable]
    # Execute the command and capture the output
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Check the return code to see if the command executed successfully
    if result.returncode == 0:
        print(f"[*] {target_tweak.rpartition('/')[-1]} inserted successfully")
    else:
        print(f"[*] Couldn't insert dylib into {target_executable}")


def fix_tweak(target_tweak: str, fix_what: str):
    command = None
    if fix_what == 'LC_ID_DYLIB':
        # Specify the command you want to run
        command = ["install_name_tool", "-id", f"@executable_path/{inject_dir_name}/{target_tweak.rpartition('/')[-1]}", target_tweak]
    elif fix_what == 'LC_LOAD_DYLIB':
        dylib_to_change = ""
        subcommand = ["otool", "-L", target_tweak]
        # Execute the subcommand and capture the output to find substrate dylib to change
        subcommand_result = subprocess.run(subcommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if subcommand_result.returncode == 0:
            matches = re.findall(r'(/[\w./-]+)', subcommand_result.stdout)
            # Skipping the first match because it's the name of the main .dylib file
            for match in matches[1:]:
                if "substrate" in match.lower():
                    dylib_to_change = match
                    break
            if dylib_to_change == "":
                print("[*] Failed to find a substrate dylib to change")
                cleanup_and_exit()
        else:
            print(f"[*] Failed to execute subcommand")
            cleanup_and_exit()

        command = ["install_name_tool", "-change", dylib_to_change,
                   f"@executable_path/{inject_dir_name}/{hooking_library}", target_tweak]
    # Execute the command and capture the output
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Check the return code to see if the command executed successfully
    if result.returncode == 0:
        print(f"[*] {target_tweak.rpartition('/')[-1]} {fix_what} fixed successfully")
    else:
        print(f"[*] Couldn't fix {fix_what} of {target_tweak.rpartition('/')[-1]}")


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
        targetTweak = input("Target tweak dylib to inject (full or relative path): ").strip().replace('"', '').replace('\'', '')
        if os.path.exists(targetTweak):
            break
        else:
            print("[!] Specified tweak is not exists\n")

    # Specify to inject directory name where we push our tweak and hooking library
    inject_dir_name = "mlinject"

    # select hooking library prompt
    hooking_lib = ["CydiaSubstrate", "Ellekit"]
    inject_lib = None
    for i in range(len(hooking_lib)):
        print(f"[{i + 1}]. {hooking_lib[i]}")

    while True:
        num = input("\nChoose a hooking library to use: ")
        if num.isdigit() and 1 <= int(num) <= 2:
            inject_lib = hooking_lib[int(num) - 1]
            if inject_lib == "CydiaSubstrate":
                inject_lib = "lib/CydiaSubstrate.framework"
                hooking_library = "CydiaSubstrate.framework/CydiaSubstrate"
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
    print(f"\n[*] {targetTweak.rpartition('/')[-1]} injection start")
    # create temp zip file
    temp_zip_file = "temp.zip"
    if shutil.copy2(targetZip, temp_zip_file) is not None:
        print("[*] Temporarily zip file created")
    else: print("[!] Couldn't create temporarily zip file")

    # read Info.plist to get some infos
    read_plist(temp_zip_file)

    # remove UISupportedDevices
    info_plist_file = f"{app_resource_dir}/Info.plist"
    unzip(temp_zip_file, info_plist_file)
    modify_plist(info_plist_file, UISupportedDevices_ans, MinimumOSVersion_ans)
    add_file_to_zip(temp_zip_file, info_plist_file, f"{app_resource_dir}")

    # work for app's main executable
    app_main_executable = f"{app_resource_dir}/{app_bundle_executable}"
    unzip(temp_zip_file, app_main_executable)
    # save entitlements of the app's main executable
    ldid_work(app_main_executable, "save")
    # remove code signature of the app's main executable
    ldid_work(app_main_executable, "remove")
    # Insert dylib into the app's main executable and add the file to the zip
    insert_dylib(app_main_executable, targetTweak.rpartition('/')[-1])
    # restore entitlements of the app's main executable
    ldid_work(app_main_executable, "restore")
    add_file_to_zip(temp_zip_file, app_main_executable, f"{app_resource_dir}")

    # create hooking lib dir in the zip file
    hooking_lib_dir_to_make = f"{app_resource_dir}/{inject_dir_name}/"
    create_dir_in_zip(temp_zip_file, hooking_lib_dir_to_make)
    # add hooking library in the zip file
    add_file_to_zip(temp_zip_file, inject_lib, hooking_lib_dir_to_make)
    # add tweak dylib in the zip file
    add_file_to_zip(temp_zip_file, targetTweak, hooking_lib_dir_to_make)
    # unzip it
    unzip(temp_zip_file, f"{hooking_lib_dir_to_make}")
    # remove code signature of the tweak dylib
    ldid_work(f"{hooking_lib_dir_to_make}{targetTweak.rpartition('/')[-1]}", "remove")
    # fix LC_ID_DYLIB, LO_LOAD_DYLIB of the tweak dylib
    fix_tweak(f"{hooking_lib_dir_to_make}{targetTweak.rpartition('/')[-1]}", "LC_ID_DYLIB")
    fix_tweak(f"{hooking_lib_dir_to_make}{targetTweak.rpartition('/')[-1]}", "LC_LOAD_DYLIB")
    # add the fixed tweak in the zip file
    add_file_to_zip(temp_zip_file, f"{hooking_lib_dir_to_make}{targetTweak.rpartition('/')[-1]}", hooking_lib_dir_to_make)
    shutil.move(temp_zip_file, f"{app_bundle_executable}_injected.ipa")

    # clean up
    cleanup_and_exit()
