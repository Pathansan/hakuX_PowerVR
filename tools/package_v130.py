import zipfile
import os
import shutil
import subprocess

apk_in = r'android/app/build/outputs/apk/debug/app-debug.apk'
apk_out_unaligned = r'android/app/build/outputs/apk/debug/HakuxPVR-v130-unaligned.apk'
apk_out_aligned = r'android/app/build/outputs/apk/debug/HakuxPVR-v130-aligned.apk'
apk_final = r'HakuxPVR-v1.30.apk'
so_path = r'android/app/src/main/jniLibs/arm64-v8a/libhakuxcore.so'

zipalign = r'C:\Users\spathania\Documents\Android\Sdk\build-tools\34.0.0\zipalign.exe'
apksigner = r'C:\Users\spathania\Documents\Android\Sdk\build-tools\34.0.0\apksigner.bat'
keystore = os.path.expanduser('~/.android/debug.keystore')

env = os.environ.copy()
env['JAVA_HOME'] = r'C:\Users\spathania\Documents\jdk-21\jdk-21.0.12.1+1'
env['PATH'] = env['JAVA_HOME'] + r'\bin;' + env.get('PATH', '')

print('Starting APK repack...')
# 1. Repack unaligned
sig_extensions = ('.sf', '.rsa', '.dsa', '.mf')
with zipfile.ZipFile(apk_in, 'r') as zin:
    with zipfile.ZipFile(apk_out_unaligned, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == 'lib/arm64-v8a/libhakuxcore.so':
                continue
            fname_lower = item.filename.lower()
            if fname_lower.startswith('meta-inf/') and any(fname_lower.endswith(ext) for ext in sig_extensions):
                continue
            zout.writestr(item, zin.read(item.filename))
        with open(so_path, 'rb') as f:
            so_bytes = f.read()
            print(f'Injecting patched libhakuxcore.so ({len(so_bytes)} bytes)...')
            zout.writestr('lib/arm64-v8a/libhakuxcore.so', so_bytes)

print('Repacked unaligned APK.')

# 2. Zipalign (4-byte alignment, page-align uncompressed .so)
if os.path.exists(apk_out_aligned): os.remove(apk_out_aligned)
subprocess.run([zipalign, '-v', '-p', '4', apk_out_unaligned, apk_out_aligned], check=True, stdout=subprocess.DEVNULL)
print('Zipalign done.')

# 3. Apksigner with debug keystore
if os.path.exists(apk_final): os.remove(apk_final)
shutil.copyfile(apk_out_aligned, apk_final)
subprocess.run([apksigner, 'sign', '--ks', keystore, '--ks-pass', 'pass:android', '--key-pass', 'pass:android', apk_final], env=env, check=True)
print('Apksigner done.')

# 4. Verify signature
res = subprocess.run([apksigner, 'verify', '--verbose', apk_final], env=env, capture_output=True, text=True)
print('Verify result:', 'VERIFIED OK' if res.returncode == 0 else 'FAILED')
print(res.stdout[:300])
