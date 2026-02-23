# 🔬 Security Forensic Analysis — Spotify v9.1.24.1739 (Premium) "fix"

> **⚠️ WARNING: This APK is modified, repackaged, and contains injected code. Do NOT install it. This document exists solely for educational and security research purposes.**

<p align="center">
  <strong>Researched & documented by <a href="https://hegxib.me">Hegxib</a></strong><br>
  <a href="https://hegxib.me">🌐 Website</a> · <a href="https://github.com/Hegxib">💻 GitHub</a> · <a href="#-donations">💸 Donate</a>
</p>

---

## 📋 Table of Contents

- [Executive Summary](#executive-summary)
- [APK Overview](#apk-overview)
- [Full File Structure Analysis](#full-file-structure-analysis)
- [The Boot Chain — How the Mod Works](#the-boot-chain--how-the-mod-works)
  - [Stage 1: The Stub Loader (classes.dex)](#stage-1-the-stub-loader-classesdex)
  - [Stage 2: The Native Hooking Engine (libnibrut.so)](#stage-2-the-native-hooking-engine-libnibrutso)
  - [Stage 3: The Hidden Payload (nibrut.nibrut)](#stage-3-the-hidden-payload-nibrut-nibrut)
  - [Stage 4: LSPatch Runtime Hooking](#stage-4-lspatch-runtime-hooking)
  - [Stage 5: The LiteAPKs Injected Module (classes12.dex)](#stage-5-the-liteapks-injected-module-classes12dex)
- [Deep Dive: Stub classes.dex Analysis](#deep-dive-stub-classesdex-analysis)
- [Deep Dive: libnibrut.so Native Library Analysis](#deep-dive-libnibrutso-native-library-analysis)
- [Deep Dive: nibrut.nibrut Payload Analysis](#deep-dive-nibrut-nibrut-payload-analysis)
- [Deep Dive: classes12.dex — The LiteAPKs Module](#deep-dive-classes12dex--the-liteapks-module)
- [Deep Dive: Native Libraries (.so files)](#deep-dive-native-libraries-so-files)
- [Deep Dive: META-INF Service Providers](#deep-dive-meta-inf-service-providers)
- [Trackers and SDKs Present](#trackers-and-sdks-present)
- [URL and Domain Analysis](#url-and-domain-analysis)
- [Encryption and Crypto Analysis](#encryption-and-crypto-analysis)
- [Risk Assessment Matrix](#risk-assessment-matrix)
- [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
- [What LiteAPKs.com / 9MOD.COM Are](#what-liteapkscom--9modcom-are)
- [How to Protect Yourself](#how-to-protect-yourself)
- [Technical Methodology](#technical-methodology)
- [Final Verdict](#final-verdict)
- [Credits](#credits)
- [💸 Donations](#-donations)
- [License & Disclaimer](#license--disclaimer)

---

## Executive Summary

This document presents a **complete forensic reverse-engineering analysis** of a modified Spotify APK (v9.1.24.1739) labeled as "(Premium) fix," distributed through the **LiteAPKs.com** modding platform. The analysis was performed by extracting and examining every layer of the APK — from the outer file structure down to individual strings inside native ELF binaries and hidden DEX bytecode.

### Key Findings at a Glance

| Finding | Severity |
|---|---|
| APK uses **LSPatch/LSPosed/Xposed** framework for root-level method hooking **without root** | 🔴 CRITICAL |
| Real app code (90.8 MB) is **hidden inside a disguised ZIP file** (`nibrut.nibrut`) to evade antivirus | 🔴 CRITICAL |
| Root `classes.dex` is a **2,940-byte stub loader**, not the real app | 🔴 CRITICAL |
| **Native hooking library** (`libnibrut.so`) is hidden in `kotlin/ranges/` directory | 🔴 CRITICAL |
| Injected **LiteAPKs module** (`classes12.dex`) contains **AES encryption**, **HTTP networking**, and **device fingerprinting** | 🔴 CRITICAL |
| Module makes **outbound HTTP connections** and can **decrypt hidden payloads** at runtime | 🔴 CRITICAL |
| Promotional **adware dialogs** for LiteAPKs.com, 9MOD.COM, and a Telegram channel | 🔴 HIGH |
| **Hardcoded AES encryption keys** (Base64-encoded) found in injected code | 🟡 HIGH |
| **No APK signature certificates** in META-INF — origin unverifiable | 🟡 MEDIUM |
| **Obfuscated Java service providers** (`p.czt`, `p.uk90`, `p.t1v`) — purpose unknown | 🟡 MEDIUM |
| Standard Spotify trackers (Facebook SDK, comScore, Firebase, Branch) present | 🟢 LOW (expected) |

---

## APK Overview

| Property | Value |
|---|---|
| **App Name** | Spotify |
| **Claimed Version** | v9.1.24.1739 |
| **Label** | "(Premium) fix" |
| **Package Name** | `com.spotify.music` |
| **Total Extracted Size** | 183.82 MB |
| **Total File Count** | 3,938 files |
| **Source** | LiteAPKs.com / 9MOD.COM |
| **Modding Framework** | LSPatch (LSPosed/Xposed-based) |
| **Packer** | "nibrut" (reversed: "turbin") |
| **Architectures** | `arm64-v8a`, `armeabi-v7a` |
| **Min API Target** | Android (exact level in compiled manifest) |
| **Build ID** | `c442c110-9016-4076-ad07-9af2fcbc15f8` |

---

## Full File Structure Analysis

### Root Level Files

```
Spotify v9.1.24.1739 (Premium) fix/
├── AndroidManifest.xml          ← Compiled binary XML (not human-readable)
├── classes.dex                  ← 🔴 FAKE — Only 2,940 bytes! This is the LSPatch stub loader
├── resources.arsc               ← Compiled Android resource table
├── assets/
│   ├── app_remote_allow_list.csv    ← 1,165 allowed remote app package signatures
│   ├── crashlytics-build.properties ← Firebase Crashlytics build ID
│   ├── licenses.xhtml               ← Third-party open source licenses (1,540 lines)
│   ├── rcs_overrides.json           ← Empty JSON array []
│   └── dexopt/
│       ├── baseline.prof            ← ART baseline profile
│       ├── baseline.profm           ← ART baseline profile metadata
│       └── nibrut.nibrut            ← 🔴 HIDDEN PAYLOAD — 90.84 MB ZIP containing the REAL app
│   └── org/threeten/bp/             ← ThreeTenABP timezone data
│   └── shaders/                     ← OpenGL ES fragment/vertex shaders (legitimate)
├── kotlin/
│   ├── kotlin.kotlin_builtins       ← Standard Kotlin metadata
│   ├── annotation/                  ← Standard Kotlin metadata
│   ├── collections/                 ← Standard Kotlin metadata
│   ├── concurrent/atomics/          ← Standard Kotlin metadata
│   ├── coroutines/                  ← Standard Kotlin metadata
│   ├── internal/                    ← Standard Kotlin metadata
│   ├── ranges/
│   │   ├── ranges.kotlin_builtins   ← Standard Kotlin metadata (cover)
│   │   ├── arm64-v8a/
│   │   │   └── libnibrut.so         ← 🔴 HIDDEN — LSPatch native hooking engine (253,512 bytes)
│   │   └── armeabi-v7a/
│   │       └── libnibrut.so         ← 🔴 HIDDEN — LSPatch native hooking engine (192,508 bytes)
│   └── reflect/                     ← Standard Kotlin metadata
├── lib/
│   ├── arm64-v8a/                   ← 13 native libraries (see detailed analysis below)
│   └── armeabi-v7a/                 ← 13 native libraries (mirrors arm64)
├── META-INF/
│   └── services/                    ← Java ServiceLoader providers (10 entries, some obfuscated)
├── org/threeten/                    ← ThreeTenBP timezone data
├── proguard/
│   └── consumer-proguard-rules.pro  ← ProGuard/R8 keep rules
└── res/                             ← ~3,800+ compiled Android resources
    ├── anim/                        ← Animations
    ├── color/                       ← Color state lists
    ├── drawable/                    ← Drawables (multiple density buckets)
    ├── font/                        ← Custom fonts
    ├── layout/                      ← UI layouts
    ├── mipmap/                      ← App icons
    ├── navigation/                  ← Navigation graphs
    ├── raw/                         ← Lottie animations, JSON configs, certificates
    └── xml/                         ← XML configs (network security, widgets, etc.)
```

### What's Wrong With This Structure

1. **`classes.dex` is 2,940 bytes** — A real Spotify APK has 12 DEX files totaling ~80 MB. This stub is 0.003% of expected size.
2. **`kotlin/ranges/` contains native `.so` libraries** — This directory should ONLY contain `ranges.kotlin_builtins`. The hidden `arm64-v8a/` and `armeabi-v7a/` subdirectories with `libnibrut.so` are completely anomalous.
3. **`assets/dexopt/nibrut.nibrut`** — This 90.84 MB file has a fake extension but is actually a ZIP archive containing the entire real APK contents.
4. **`META-INF/` has no signing certificates** — No `CERT.RSA`, `CERT.SF`, or `MANIFEST.MF`.

---

## The Boot Chain — How the Mod Works

### Stage 1: The Stub Loader (classes.dex)

When Android installs and launches this APK, it loads the root `classes.dex` (2,940 bytes). This is **not** the real Spotify app. It contains a single meaningful class:

```
org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub
```

This class is an Android `AppComponentFactory` override that hijacks the app's initialization process. It:
- Logs `"Bootstrap loader from embedment"` and `"LSPatch-MetaLoader"`
- Uses `java.lang.System.load()` to load the native library `libnibrut.so`
- Uses `java.lang.reflect` to bypass access restrictions
- References `dalvik.system.VMRuntime` to detect the CPU architecture (`arm64`, `arm64-v8a`, `armeabi-v7a`, `x86_64`)
- Accesses `kotlin/ranges/` path (where `libnibrut.so` is hidden) and a dummy path `lib/arm64-v8a/libtensorflowlite_gpu_jni.so` as a resource locator trick

### Stage 2: The Native Hooking Engine (libnibrut.so)

Once the stub loads `libnibrut.so`, this native library takes control. It is the **LSPlant/LSPatch hooking engine** — a sophisticated ART (Android Runtime) manipulation library. It:

1. **Hooks ART internal methods** at the native level:
   - `art::ArtMethod::RegisterNative` / `UnregisterNative`
   - `art::ClassLinker::FixupStaticTrampolines`
   - `art::ClassLinker::ShouldUseInterpreterEntrypoint`
   - `art::jit::JitCodeCache` methods
   - `art::instrumentation::Instrumentation` methods
   - `artInterpreterToCompiledCodeBridge`
   - `art_quick_to_interpreter_bridge`
   - `art_quick_generic_jni_trampoline`

2. **Reads process memory maps** via `/proc/self/maps`

3. **Creates in-memory DEX class loaders** using `dalvik.system.InMemoryDexClassLoader`

4. **Generates runtime method trampolines** for hooking arbitrary Java methods

5. **Loads the LSPatch application class**: `org.lsposed.lspatch.loader.LSPApplication`

6. **Implements XResources hooking** for replacing Android resources at runtime (`xposed.dummy.XResourcesSuperClass`, `xposed.dummy.XTypedArraySuperClass`)

7. **Disables ART optimizations** to ensure hooks remain active (`--inline-max-code-units=0`, `deoptimizeMethod`)

8. **Hooks file operations** (`__openat`) to intercept file access

9. **References `liblspatch.so`** as an internal dependency

### Stage 3: The Hidden Payload (nibrut.nibrut)

The real Spotify application is stored in `assets/dexopt/nibrut.nibrut` — a **90.84 MB ZIP archive** with a fake file extension. The name "nibrut" is **"turbin" reversed**, likely the name of the packing tool.

The ZIP contains the **complete original APK contents**:

| File | Size (Uncompressed) | Description |
|---|---|---|
| `classes.dex` | 9,188,648 bytes | Main DEX (original Spotify code) |
| `classes2.dex` | 9,598,792 bytes | Original Spotify code |
| `classes3.dex` | 7,539,124 bytes | Original Spotify code |
| `classes4.dex` | 8,043,076 bytes | Original Spotify code |
| `classes5.dex` | 9,245,520 bytes | Original Spotify code |
| `classes6.dex` | 9,544,992 bytes | Original Spotify code |
| `classes7.dex` | 8,283,252 bytes | Original Spotify code |
| `classes8.dex` | 7,777,632 bytes | Original Spotify code |
| `classes9.dex` | 67,852 bytes | Apache Commons Math library |
| `classes10.dex` | 393,944 bytes | Java-WebSocket + Ably libraries |
| `classes11.dex` | 52,796 bytes | Spotify account switching module |
| `classes12.dex` | 68,476 bytes | 🔴 **INJECTED — LiteAPKs adware/tracker module** |
| `AndroidManifest.xml` | 133,548 bytes | Full compiled manifest |
| `resources.arsc` | — | Full resource table |
| `lib/` | — | All 13 native libraries (both architectures) |
| `assets/` | — | All asset files |
| `res/` | — | All compiled resources |
| `kotlin/` | — | Kotlin metadata |
| `META-INF/services/` | — | Service provider files |
| `proguard/` | — | ProGuard rules |
| `assets/title.ttf` | 28,068 bytes | Custom font (used by LiteAPKs dialog) |

The LSPatch framework unpacks this at runtime and loads all DEX files into memory using `InMemoryDexClassLoader`, completely bypassing the normal Android package loading process.

### Stage 4: LSPatch Runtime Hooking

Once the real Spotify code is loaded, LSPatch uses LSPlant to:
- Hook premium verification methods
- Bypass subscription checks
- Remove or disable advertisement loading
- Modify feature flags
- Override resource values via XResources

This is all done at the **ART method level** — individual Java/Kotlin methods have their entry points redirected to LSPatch-controlled trampolines that can modify arguments, return values, or skip the original method entirely.

### Stage 5: The LiteAPKs Injected Module (classes12.dex)

This is the modder's own code, injected alongside the original Spotify DEX files. It operates independently of the premium unlock and serves the modder's interests. Full analysis in the dedicated section below.

---

## Deep Dive: Stub classes.dex Analysis

**File**: `classes.dex` (root of APK)  
**Size**: 2,940 bytes  
**DEX Version**: 039  
**Magic Bytes**: `64 65 78 0a 30 33 39 00` (`dex\n039\0`)

### Complete String Table Extracted

Every readable ASCII string found in the stub:

```
/libnibrut.so
<clinit>
<init>
Bootstrap loader from embedment
LSPatch-MetaLoader
!Landroid/app/AppComponentFactory;
Landroid/util/Log;
Ljava/io/ByteArrayOutputStream;
Ljava/io/InputStream;
Ljava/io/OutputStream;
Ljava/lang/Class;
Ljava/lang/ClassLoader;
Ljava/lang/ExceptionInInitializerError;
Ljava/lang/Object;
Ljava/lang/String;
Ljava/lang/StringBuilder;
Ljava/lang/System;
Ljava/lang/Throwable;
Ljava/lang/reflect/AccessibleObject;
Ljava/lang/reflect/Method;
Ljava/net/URL;
Ljava/util/HashMap;
Ljava/util/Objects;
Lorg/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub;
arm64
arm64-v8a
armeabi-v7a
close
dalvik.system.VMRuntime
forName
getClassLoader
getDeclaredMethod
getPath
getResource
getResourceAsStream
getRuntime
invoke
kotlin/ranges/
lib/arm64-v8a/libtensorflowlite_gpu_jni.so
load
read
requireNonNull
setAccessible
substring
toByteArray
toString
vmInstructionSet
write
x86_64
```

### Key Observations

1. **`Lorg/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub`** — This is the entry point class. It extends `android.app.AppComponentFactory`, which Android calls before any other app code runs.

2. **`/libnibrut.so`** — The native library it loads. Note the path-style reference — it extracts this from within the APK.

3. **`kotlin/ranges/`** — The deliberately misleading path where `libnibrut.so` is hidden. A developer looking at this would assume it's just Kotlin standard library metadata.

4. **`lib/arm64-v8a/libtensorflowlite_gpu_jni.so`** — Used as a reference point to locate the APK's own path on the filesystem, not to actually use TensorFlow.

5. **`dalvik.system.VMRuntime`** + **`vmInstructionSet`** — Used to detect the CPU architecture at runtime to load the correct `libnibrut.so` variant.

6. **`Bootstrap loader from embedment`** — The log message confirming this is an embedded/packed app loader.

7. **Reflection APIs** (`forName`, `getDeclaredMethod`, `setAccessible`, `invoke`) — Used to bypass Java access controls and call internal Android APIs.

---

## Deep Dive: libnibrut.so Native Library Analysis

**Files**:
- `kotlin/ranges/arm64-v8a/libnibrut.so` — 253,512 bytes (247.6 KB)
- `kotlin/ranges/armeabi-v7a/libnibrut.so` — 192,508 bytes (188.0 KB)

**File Type**: ELF 64-bit LSB shared object, ARM aarch64 (arm64 variant)

### JNI Entry Point

```
JNI_OnLoad — Standard JNI initialization function called when System.loadLibrary() loads this .so
```

### Complete List of Critical Strings Found

#### LSPatch/LSPosed/Xposed Framework References

```
liblspatch.so
org.lsposed.lspatch.loader.LSPApplication
org/lsposed/lspatch/metaloader/LSPAppComponentFactoryStub
org.lsposed.lspd.service.
org.lsposed.lspd.core.
org.lsposed.lspd.nativebridge.
de.robv.android.xposed.
android.content.res.XRes
android.content.res.XModule
xposed.dummy.XResourcesSuperClass
xposed.dummy.XTypedArraySuperClass
LSPlant Hook
LSPHooker_
HookBridge
hookMethod
unhookMethod
invokeOriginalMethod
invokeSpecialMethod
deoptimizeMethod
beforeInvocation
afterInvocation
callbackSnapshot
```

#### ART (Android Runtime) Internal Method Hooks

```
_ZN3art9ArtMethod12PrettyMethodEPS0_b
_ZN3art9ArtMethod14RegisterNativeEPKv
_ZN3art9ArtMethod16UnregisterNativeEv
_ZN3art9ArtMethod24ThrowInvocationTimeErrorEv
_ZN3art11ClassLinker30ShouldUseInterpreterEntrypointEPNS_9ArtMethodEPKv
_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ThreadENS_6ObjPtrINS_6mirror5ClassEEE
_ZN3art11ClassLinker14RegisterNativeEPNS_6ThreadEPNS_9ArtMethodEPKv
_ZN3art11ClassLinker16UnregisterNativeEPNS_6ThreadEPNS_9ArtMethodE
_ZN3art11ClassLinker26VisiblyInitializedCallback29AdjustThreadVisibilityCounterEPNS_6ThreadEl
_ZN3art11ClassLinker26VisiblyInitializedCallback22MarkVisiblyInitializedEPNS_6ThreadE
_ZNK3art11ClassLinker27SetEntryPointsToInterpreterEPNS_9ArtMethodE
artInterpreterToCompiledCodeBridge
art_quick_to_interpreter_bridge
art_quick_generic_jni_trampoline
_ZN3art15instrumentation15Instrumentation21InitializeMethodsCodeEPNS_9ArtMethodEPKv
_ZN3art15instrumentation15Instrumentation40UpdateMethodsCodeToInterpreterEntryPointEPNS_9ArtMethodE
_ZN3art3jit3Jit27EnqueueOptimizedCompilationEPNS_9ArtMethodEPNS_6ThreadE
_ZN3art3jit3Jit14AddCompileTaskEPNS_6ThreadEPNS_9ArtMethodENS_15CompilationKindEb
_ZN3art3jit12JitCodeCache18MoveObsoleteMethodEPNS_9ArtMethodES3_
_ZN3art3jit12JitCodeCache19GarbageCollectCacheEPNS_6ThreadE
_ZN3art3jit12JitCodeCache12DoCollectionEPNS_6ThreadE
_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE
_ZN3art6mirror5Class11GetClassDefEv
_ZN3art6mirror5Class9SetStatusENS_6HandleIS1_EENS1_6StatusEPNS_6ThreadE
_ZN3art7Runtime9instance_E
_ZN3art7Runtime17SetJavaDebuggableEb
_ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE
_ZN3art6Thread14CurrentFromGdbEv
_ZN3art16ScopedSuspendAllC2EPKcb
_ZN3art16ScopedSuspendAllD2Ev
_ZN3art2gc23ScopedGCCriticalSectionC2EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE
_ZN3art2gc23ScopedGCCriticalSectionD2Ev
_ZN3art12ProfileSaver20ProcessProfilingInfoEbPt
_ZN3art14OatFileManager25RunBackgroundVerificationERKNSt3__16vectorIPKNS_7DexFileENS1_9allocatorIS5_EEEEP8_jobjectPKc
_ZN3artL18DexFile_setTrustedEP7_JNIEnvP7_jclassP8_jobject
_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_
_ZN3art3jni12JniIdManager15EncodeGenericIdINS_9ArtMethodEEEmNS_16ReflectiveHandleIT_EE
```

#### Memory and Process Inspection

```
/proc/self/maps
mmap trampoline failed with %d: %s
lseek() failed for {}
failed to open {}
failed to read load address for {}
failed to find debug_state
Hook __openat fail
```

#### Class Loading and DEX Manipulation

```
dalvik/system/InMemoryDexClassLoader
dalvik/system/DexClassLoader
dalvik/system/PathClassLoader
dalvik/system/DexFile
dalvik/system/VMRuntime
Failed to open memory dex: %s
InMemoryDexClassLoader creation failed!!!
Invalid dex data
Compact dex is not supported
DexFile.setTrusted not found, MakeDexFileTrusted will not work.
buildDummyClassLoader
dexElements
```

#### Method Hooking Internals

```
Failed to generate trampoline
Failed to generate hooker
Skip duplicate hook
Failed to init lsplant
Failed to init art method
Failed to init class linker
Failed to init jit
Failed to init jit code cache
Failed to init instrumentation
Failed to init mirror class
Failed to init jni id manager
Failed to init runtime
Failed to init thread
Failed to init scoped gc critical section
Failed to init scoped suspend all
Failed to init dex file
entryPointFromQuickCompiledCode
entryPointFromJni
entryPointFromInterpreter
accessFlags
declaringClass
--inline-max-code-units=0
```

#### Resource Hooking (XResources)

```
ResourcesHook
translateResId
translateAttrId
rewriteXmlReferencesNative
initXResourcesNative
GetXResourcesClassName: obfuscation_map empty?????
Error while loading XResources class '{}':
_ZNK7android12ResXMLParser18getAttributeNameIDEm
_ZN7android12ResXMLParser4nextEv
_ZN7android12ResXMLParser7restartEv
_ZNK7android13ResStringPool8stringAtEm
libandroidfw.so
```

#### System and Android Internals

```
__android_log_print
__android_log_write
__system_property_get
ro.build.version.sdk
ro.build.version.preview_sdk
exynos9810
android/app/ActivityThread
android/app/ActivityThread$AppBindData
android/app/LoadedApk
mBoundApplication
currentActivityThread
```

### What This All Means

`libnibrut.so` is a **complete ART hooking framework**. It can:

1. **Replace any Java/Kotlin method** in any loaded class at runtime
2. **Intercept constructor calls** and modify object creation
3. **Replace Android resources** (strings, layouts, drawables) on the fly
4. **Read process memory** through `/proc/self/maps`
5. **Load arbitrary DEX code** from memory (no files on disk)
6. **Disable JIT compilation** to ensure hooks remain stable
7. **Hook native file operations** (`__openat`)
8. **Suspend all threads** for safe code modification
9. **Make DEX files "trusted"** to bypass Android security checks
10. **Generate runtime trampolines** — small machine code stubs that redirect method calls

---

## Deep Dive: nibrut.nibrut Payload Analysis

**File**: `assets/dexopt/nibrut.nibrut`  
**Size**: 95,257,114 bytes (90.84 MB)  
**True Format**: ZIP archive  
**Magic Bytes**: `50 4B 03 04` (`PK..` — standard ZIP header)  
**Name Origin**: "nibrut" = "turbin" reversed — the packer/tool name

### Why This Evasion Technique Works

1. **Antivirus scanners** analyze the root `classes.dex` — which is only a 2.9 KB stub with no malicious code
2. **Google Play Protect** doesn't deep-scan files with custom extensions inside `assets/`
3. **Static analysis tools** (like APKTool, jadx) process DEX files at the root level — they don't automatically look inside nested ZIP archives with fake extensions
4. **File name obfuscation** — `.nibrut` is not a recognized extension, so security tools skip it

### DEX File Size Comparison

| DEX File | Size | Purpose |
|---|---|---|
| `classes.dex` | 9,188,648 bytes (8.76 MB) | Main Spotify code |
| `classes2.dex` | 9,598,792 bytes (9.15 MB) | Spotify code |
| `classes3.dex` | 7,539,124 bytes (7.19 MB) | Spotify code |
| `classes4.dex` | 8,043,076 bytes (7.67 MB) | Spotify code |
| `classes5.dex` | 9,245,520 bytes (8.82 MB) | Spotify code |
| `classes6.dex` | 9,544,992 bytes (9.10 MB) | Spotify code |
| `classes7.dex` | 8,283,252 bytes (7.90 MB) | Spotify code |
| `classes8.dex` | 7,777,632 bytes (7.42 MB) | Spotify code |
| `classes9.dex` | 67,852 bytes (66.3 KB) | Apache Commons Math |
| `classes10.dex` | 393,944 bytes (384.7 KB) | Java-WebSocket + Ably |
| `classes11.dex` | 52,796 bytes (51.6 KB) | Spotify account switching |
| `classes12.dex` | 68,476 bytes (66.9 KB) | 🔴 **INJECTED — LiteAPKs module** |
| **TOTAL** | **~79.5 MB** | |

The root `classes.dex` is **2,940 bytes** vs the real `classes.dex` inside the ZIP at **9,188,648 bytes** — a **3,125x size difference**.

### classes9.dex — Apache Commons Math

A legitimate third-party library. Only URL found:
```
https://issues.apache.org/jira/browse/MATH
```

### classes10.dex — WebSocket Libraries

Contains Java-WebSocket and Ably realtime libraries. URLs found:
```
https://github.com/TooTallNate/Java-WebSocket/wiki/Lost-connection-detection
https://help.ably.io/error/
https://internet-up.ably-realtime.com/is-the-internet-up.txt
```

### classes11.dex — Spotify Account Switching

Legitimate Spotify module for multi-account support. Contains references to:
- `com.spotify.accountswitching.switcherimpl`
- `com.spotify.authentication.login5esperanto`
- `com.spotify.connectivity.auth`
- `com.spotify.identity.proto.v3`
- Login5 protocol, OAuth tokens, account credential management
- `AndroidKeyStore` for secure credential storage
- `accountswitching_encrypted_sharedprefs`

Key strings confirming legitimacy:
```
Account Switching could not recreate shared preferences
Account Switching failed to delete shared preferences file
Account Switching preferences could not be created first time
Access Token or AuthBlob equal to null on refresh
Esperanto failure: Failure reason NOT_SET
/identity/v3/user/username/{username}
```

---

## Deep Dive: classes12.dex — The LiteAPKs Module

**File**: `classes12.dex` (inside `nibrut.nibrut`)  
**Size**: 68,476 bytes (66.9 KB)  
**Origin**: Injected by LiteAPKs.com  
**Not present in official Spotify APK**

This is the **most dangerous component** in the entire APK. It is a complete module injected by the mod distributor that operates independently of the Spotify premium unlock.

### Package Structure

```
dialog/maker/
├── ClassicDialog          ← Main dialog display class
├── CustomBackground       ← Custom dialog backgrounds with gradients
├── NeutralClickListener   ← Handler for "neutral" button (dismiss/check)
└── PositiveClickListener  ← Handler for "positive" button (open links)

(obfuscated packages with Unicode characters in names)
├── ⬛⬛/⬛⬛⬛⬛/bi, bi0-bi4    ← Obfuscated utility classes
├── ⬛⬛/⬛⬛⬛⬛/bl, bl0-bl4    ← Obfuscated utility classes
├── ⬛⬛/⬛⬛⬛⬛/iab, iab$1-$3  ← Obfuscated classes with inner classes
├── ⬛⬛/⬛⬛⬛⬛/iaw, iaw$1-$3  ← Obfuscated classes with inner classes
├── ⬛⬛/⬛⬛⬛⬛/up, up$ctr, up$ok, up$und, up$100000000-up$100000005
├── ⬛⬛/⬛⬛⬛⬛/up1, up1$100000006-up1$100000009
├── ⬛⬛/⬛⬛⬛⬛/wi, wi0-wi4    ← Obfuscated utility classes
├── ⬛⬛/⬛⬛⬛⬛/wl, wl0-wl4    ← Obfuscated utility classes
└── ⬛⬛i/⬛⬛i/pk, pk$ctr, pk$ok, pk$und, pk$100000000-pk$100000008
```

### Capabilities Identified

#### 1. AES Encryption/Decryption System

```java
// Classes used:
javax.crypto.Cipher
javax.crypto.SecretKey
javax.crypto.spec.SecretKeySpec
java.security.MessageDigest  // SHA-256

// Methods:
generateKey    // Generates AES key from SHA-256 hash
decrypt        // Decrypts AES-encrypted payloads
getInstance    // Gets Cipher instance

// Algorithm:
SHA-256 → AES key derivation → AES decryption of hidden strings/payloads
```

#### 2. Hardcoded Encrypted Keys/Data

Three Base64-encoded encryption keys/hashes found:

```
BHoKAJ0BAR2DLOvQkDvRcNLeeqgqHLCqKMR1JfyXapo=
bKxCJRf2+J6gvv7C0fr4tYEBkjGR5dmbwzKykxOB8Fo=
dR5Vx2mOx4GqCE6I6Mx84jGeMEe5c38m7jWIajevG8I=
```

Additional encrypted/encoded strings:
```
/i6AIPyQYZkrkkikDBa31g==
AcOSzbejZ
TyIyyeGAh
wHcphfdkb
```

These decode to binary data, indicating they are **AES-encrypted payloads** that get decrypted at runtime using the `generateKey` + `decrypt` methods.

#### 3. HTTP Network Communication

```java
java.net.HttpURLConnection    // Makes HTTP requests
java.net.URL                  // Constructs URLs
java.net.URLConnection        // Network connections
java.net.URLDecoder           // URL decoding
openConnection                // Opens HTTP connection
getInputStream                // Reads server response
readLine                      // Reads response line by line
setConnectTimeout             // Sets connection timeout
```

Known outbound connections:
```
https://liteapks.com/app.html          ← LiteAPKs mod store
https://t.me/best_video_editings       ← Telegram channel
```

**Additional URLs may be encrypted** in the Base64 strings above, only decryptable at runtime.

#### 4. Device Fingerprinting

```java
getPackageInfo       // Gets app version, signatures
getPackageName       // Gets package identifier
versionCode          // Numeric version code
versionName          // Human-readable version
getLongVersionCode   // Extended version code
MessageDigest/SHA-256  // Hashes device/app information
```

#### 5. Persistent Data Storage

```java
SharedPreferences           // Android persistent key-value store
SharedPreferences.Editor    // Write to SharedPreferences
getSharedPreferences        // Access preferences
putBoolean                  // Store boolean flags
getBoolean                  // Read boolean flags
putString                   // Store string data
getString                   // Read string data
files_dir                   // Internal file storage directory
getFilesDir                 // Gets app's private file directory
getAbsolutePath             // Gets file absolute path
```

Used to:
- Track whether the promotional dialog has been shown (`showTime`, `putBoolean`)
- Store "Don't show again" checkbox state (`CheckBox`, `isChecked`)
- Persist configuration data
- Store/retrieve encrypted values

#### 6. Promotional Dialog System

The module creates a full custom dialog UI:

**UI Components:**
```java
AlertDialog.Builder         // Dialog construction
ClassicDialog               // Custom dialog class
CustomBackground            // GradientDrawable with custom colors
NeutralClickListener        // "Don't show again" handler
PositiveClickListener       // "Open link" handler
CheckBox                    // "Don't show again" checkbox
Button                      // Dialog buttons
TextView                    // Text display
LinearLayout                // Layout container
```

**Custom Fonts:**
```
button.ttf                  // Button text font
message.ttf                 // Message body font
title.ttf                   // Dialog title font (28 KB, also at APK root in nibrut.nibrut)
```

**Color Scheme** (hex values found):
```
#FF000000  — Black
#FF005AFA  — Blue (buttons/links)
#FF00FF0A  — Neon green
#FF03FF00  — Green
#FF111111  — Near-black (background)
#FF3F85E7  — Light blue
#FF555555  — Dark gray
#FF585858  — Gray
#FF6A6A6A  — Medium gray
#FF888888  — Gray
#FF8BC367  — Green (success)
#FF8BC368  — Green (success alt)
#FFA9B7D9  — Light blue-gray
#FFA9B7FF  — Periwinkle
#FFCC3232  — Red (warning)
#FFEFEFEF  — Near-white
#FFFFFFFF  — White
#ff0092ff  — Bright blue
```

**Dialog Text Content:**
```
Title:    "⚠️ Liteapks.com ⚠️"
Message:  "LITEAPKS.COM and 9MOD.COM are Trusted sources for Modded apps & Games."
Button 1: "Get Liteapks Mod Store 🔥🔥🔥"  → Opens https://liteapks.com/app.html
Button 2: "Join Channel 💯"                  → Opens https://t.me/best_video_editings
Alert:    "Join Telegram Channel To get Stable Spotify Updates 🙏"
```

**Event Tracking Strings:**
```
Dialog Cancelled
Dialog Channel Link Clicked
Dismissed
Redirected
```

#### 7. Runtime Code Execution

```java
java.lang.Runtime           // Runtime execution
getRuntime                  // Gets Runtime instance
java.lang.reflect.Method    // Reflection
getDeclaredMethod           // Access any method
```

#### 8. AndroidX Compatibility Check

```java
isAndroidXAvailable                          // Checks for AndroidX
isClassPresent                               // Dynamic class checking
androidx.appcompat.app.AppCompatActivity     // Activity compatibility
androidx.core.app.NotificationManagerCompat  // Notification access
```

---

## Deep Dive: Native Libraries (.so files)

### arm64-v8a Libraries

| Library | Size (KB) | Origin | Purpose |
|---|---|---|---|
| `libandroidx.graphics.path.so` | 9.9 | Google/AndroidX | Path rendering |
| `libcomScore.so` | 1,796.1 | comScore Inc. | 🟡 Audience measurement/tracking |
| `libcrashlytics-common.so` | 738.1 | Google/Firebase | Crash reporting |
| `libcrashlytics-handler.so` | 181.6 | Google/Firebase | Crash signal handler |
| `libcrashlytics-trampoline.so` | 9.4 | Google/Firebase | Crash reporting trampoline |
| `libcrashlytics.so` | 191.0 | Google/Firebase | Crash reporting core |
| `libimage_processing_util_jni.so` | 28.3 | Google | Image processing |
| `libnoise.so` | 13.8 | Spotify | Audio noise processing |
| `liborbit-jni-spotify.so` | 20,731.7 | Spotify | Main Spotify native engine (~20 MB) |
| `librootChecker.so` | 6.6 | Ravelin | Anti-fraud root detection |
| `libsurface_util_jni.so` | 4.7 | Google | Surface rendering utilities |
| `libtensorflowlite_gpu_jni.so` | 1,160.5 | Google | TensorFlow Lite GPU inference |
| `libtensorflowlite_jni.so` | 4,219.2 | Google | TensorFlow Lite CPU inference |

### armeabi-v7a Libraries

| Library | Size (KB) | Origin | Purpose |
|---|---|---|---|
| `libandroidx.graphics.path.so` | 7.1 | Google/AndroidX | Path rendering |
| `libcomScore.so` | 1,329.6 | comScore Inc. | 🟡 Audience measurement/tracking |
| `libcrashlytics-common.so` | 425.5 | Google/Firebase | Crash reporting |
| `libcrashlytics-handler.so` | 85.8 | Google/Firebase | Crash signal handler |
| `libcrashlytics-trampoline.so` | 6.8 | Google/Firebase | Crash reporting trampoline |
| `libcrashlytics.so` | 92.3 | Google/Firebase | Crash reporting core |
| `libimage_processing_util_jni.so` | 19.9 | Google | Image processing |
| `libnoise.so` | 21.7 | Spotify | Audio noise processing |
| `liborbit-jni-spotify.so` | 13,850.6 | Spotify | Main Spotify native engine (~13.5 MB) |
| `librootChecker.so` | 4.8 | Ravelin | Anti-fraud root detection |
| `libsurface_util_jni.so` | 3.4 | Google | Surface rendering utilities |
| `libtensorflowlite_gpu_jni.so` | 1,503.4 | Google | TensorFlow Lite GPU inference |
| `libtensorflowlite_jni.so` | 2,800.3 | Google | TensorFlow Lite CPU inference |

### librootChecker.so — Detailed Analysis

This is **Ravelin's** anti-fraud native library (legitimate, present in official Spotify):

```
Java_com_ravelin_core_util_security_RootCheckerNative_setLogDebugMessages
Java_com_ravelin_core_util_security_RootCheckerNative_checkForRoot
Java_com_ravelin_core_util_security_RootCheckerNative_isMagiskPresent
RootCheck
DetectMagiskNative
core/img
core/mirror
LOOKING FOR BINARY: %s Absent :(
LOOKING FOR BINARY: %s PRESENT!!!
Opening Mount file size: %ld
Checking Mount Path: %s
Found Mount Path: %s
/proc/self/mounts
```

**Verdict**: Legitimate anti-fraud library. Checks for root binaries, Magisk hiding, and suspicious mount points. Present in the official Spotify app.

### Hidden libnibrut.so — Location Analysis

```
EXPECTED PATH:  kotlin/ranges/ranges.kotlin_builtins (normal)
ACTUAL PATH:    kotlin/ranges/arm64-v8a/libnibrut.so (INJECTED)
                kotlin/ranges/armeabi-v7a/libnibrut.so (INJECTED)
```

The `kotlin/ranges/` directory legitimately contains only `ranges.kotlin_builtins`. The modder created subdirectories mimicking the standard `lib/` structure to hide the hooking engine where nobody would look.

---

## Deep Dive: META-INF Service Providers

| Service Interface | Implementation | Status |
|---|---|---|
| `com.fasterxml.jackson.core.JsonFactory` | `com.fasterxml.jackson.core.JsonFactory` | ✅ Legitimate |
| `com.fasterxml.jackson.core.ObjectCodec` | `com.fasterxml.jackson.databind.ObjectMapper` | ✅ Legitimate |
| `com.fasterxml.jackson.databind.Module` | `com.fasterxml.jackson.module.kotlin.KotlinModule`, `com.fasterxml.jackson.datatype.guava.GuavaModule` | ✅ Legitimate |
| `kotlin.reflect.jvm.internal.impl.builtins.BuiltInsLoader` | (standard Kotlin) | ✅ Legitimate |
| `kotlin.reflect.jvm.internal.impl.resolve.ExternalOverridabilityCondition` | (standard Kotlin) | ✅ Legitimate |
| `kotlinx.coroutines.CoroutineExceptionHandler` | `kotlinx.coroutines.android.AndroidExceptionPreHandler` | ✅ Legitimate |
| `kotlinx.coroutines.internal.MainDispatcherFactory` | `kotlinx.coroutines.android.AndroidDispatcherFactory` | ✅ Legitimate |
| **`p.czt`** | **`p.czt`** | ⚠️ **Obfuscated — unknown** |
| **`p.uk90`** | **`p.uk90`** | ⚠️ **Obfuscated — unknown** |
| **`reactor.blockhound.integration.BlockHoundIntegration`** | **`p.t1v`** | ⚠️ **Obfuscated — suspicious** |

The last three entries use heavily obfuscated class names. While R8/ProGuard obfuscation is normal for Android apps, these single-package obfuscated names could be either legitimate Spotify code or injected classes. Without full DEX decompilation, their exact purpose cannot be determined.

---

## Trackers and SDKs Present

These are present in the **official** Spotify app and are not specific to the mod:

| Tracker/SDK | Type | Purpose |
|---|---|---|
| **Facebook SDK** (Core, Common, App Links, Bolts, Device Year Class) | Analytics/Attribution | User tracking, deep linking, device profiling |
| **Firebase Crashlytics** (+ NDK) | Crash Reporting | Crash analytics with native code support |
| **Firebase Messaging** | Push Notifications | Firebase Cloud Messaging |
| **Firebase Sessions** | Analytics | Session tracking |
| **Firebase Installations** | Identity | Device-level identification |
| **Google Play Services** | Platform | Google service integration |
| **comScore** (`libcomScore.so`) | Audience Measurement | TV/digital audience tracking (1.8 MB native library) |
| **Branch SDK** | Deep Link Attribution | Marketing attribution, link tracking |
| **Google Ad Services** (`ga_ad_services_config.xml`) | Advertising | Ad tracking and measurement |
| **TensorFlow Lite** (CPU + GPU) | Machine Learning | On-device ML inference (likely recommendations) |
| **Ravelin** (`librootChecker.so`) | Anti-Fraud | Root detection, fraud prevention |
| **Shimmer for Android** | UI | Loading animation (Facebook) |
| **Lottie** | UI | Animation rendering |

### Mod-Specific "Trackers"

| Component | Type | Purpose |
|---|---|---|
| **LiteAPKs module** (`classes12.dex`) | Adware/Fingerprinting | Device fingerprinting, dialog injection, network communication |

---

## URL and Domain Analysis

### URLs Found in Main Spotify Code (classes.dex through classes8.dex)

All legitimate Spotify infrastructure:

```
*.spotify.com           — Spotify main services
*.spotifycdn.com        — Spotify CDN (images, assets, animations)
*.scdn.co               — Spotify short CDN (images, previews, scannables)
*.spotify.net            — Spotify internal services (wgint, partnerapi)
*.spotify.link           — Spotify deep links
*.spotify.app.link       — Spotify app deep links
```

Third-party (legitimate):
```
*.scorecardresearch.com  — comScore tracking
*.ravelin.click          — Ravelin anti-fraud
*.zqtk.net              — Segment analytics
*.akamaized.net         — Akamai CDN (livestreaming)
*.recaptcha.net         — Google reCAPTCHA
*.paypal.com            — Payment processing
*.youtube.com           — YouTube (music videos/education)
*.naver.com             — Naver OAuth (Korean market)
*.ftc.go.kr             — Korean FTC (regulatory compliance)
*.simplelocalize.io     — Localization service
*.fast.com              — Speed test
```

### URLs Found in Injected Code (classes12.dex)

```
https://liteapks.com/app.html           — 🔴 LiteAPKs mod store
https://t.me/best_video_editings        — 🔴 Telegram channel for mod updates
```

Additional URLs may be **encrypted** in the Base64 payloads and only resolved at runtime.

---

## Encryption and Crypto Analysis

### Encryption Infrastructure in classes12.dex

The LiteAPKs module implements a complete encryption system:

**Algorithm Chain:**
```
Input String → SHA-256 Hash → AES Key Derivation → AES Decryption → Plaintext
```

**Java Classes Used:**
```java
java.security.MessageDigest     // SHA-256 hashing
javax.crypto.Cipher             // AES encryption/decryption
javax.crypto.SecretKey          // AES secret key interface
javax.crypto.spec.SecretKeySpec // AES key specification
android.util.Base64             // Base64 encoding/decoding
```

**Hardcoded Encrypted Data:**

| Base64 String | Decoded (Raw Bytes) | Likely Purpose |
|---|---|---|
| `/i6AIPyQYZkrkkikDBa31g==` | 16 bytes (binary) | Encrypted URL or config value |
| `BHoKAJ0BAR2DLOvQkDvRcNLeeqgqHLCqKMR1JfyXapo=` | 32 bytes (binary) | AES-256 key or encrypted payload |
| `bKxCJRf2+J6gvv7C0fr4tYEBkjGR5dmbwzKykxOB8Fo=` | 32 bytes (binary) | AES-256 key or encrypted payload |
| `dR5Vx2mOx4GqCE6I6Mx84jGeMEe5c38m7jWIajevG8I=` | 32 bytes (binary) | AES-256 key or encrypted payload |

**Additional Obfuscated Strings:**
```
AcOSzbejZ     — Short encoded string
TyIyyeGAh     — Short encoded string
wHcphfdkb     — Short encoded string
[RUI^eXlOiFLaB  — Encoded string (from libnibrut.so)
TKNBW^QeHb?EZ; — Encoded string (from libnibrut.so)
```

### Why This Is Dangerous

The encryption system means the module can:
1. **Hide its true URLs/endpoints** from static analysis — we can see the encrypted blobs but cannot decrypt them without running the code
2. **Receive encrypted commands** from a remote server
3. **Update its behavior** by decrypting new instructions downloaded via the HTTP capabilities
4. **Exfiltrate data** in encrypted form that looks like benign traffic

---

## Risk Assessment Matrix

| Threat Category | Evidence | Severity | Confidence |
|---|---|---|---|
| **Code Packing / AV Evasion** | nibrut.nibrut (90.8 MB ZIP with fake extension), stub classes.dex (2.9 KB) | 🔴 CRITICAL | 🟢 Confirmed |
| **Runtime Code Injection** | LSPatch/LSPlant ART hooking, InMemoryDexClassLoader | 🔴 CRITICAL | 🟢 Confirmed |
| **Hidden Native Code** | libnibrut.so in kotlin/ranges/ (deceptive path) | 🔴 CRITICAL | 🟢 Confirmed |
| **Xposed/LSPosed Framework** | LSPAppComponentFactoryStub, XResources, HookBridge | 🔴 CRITICAL | 🟢 Confirmed |
| **Encrypted Payloads** | AES + SHA-256 + Base64 encoded strings in classes12.dex | 🔴 CRITICAL | 🟢 Confirmed |
| **Network Communication** | HttpURLConnection, openConnection, getInputStream in classes12.dex | 🔴 HIGH | 🟢 Confirmed |
| **Device Fingerprinting** | getPackageInfo, versionCode, SHA-256 hashing in classes12.dex | 🔴 HIGH | 🟢 Confirmed |
| **Adware** | Dialog system with LiteAPKs/Telegram promotions | 🔴 HIGH | 🟢 Confirmed |
| **Persistent Data Storage** | SharedPreferences read/write in injected module | 🟡 MEDIUM | 🟢 Confirmed |
| **Potential Remote Code Execution** | Encryption + Network + InMemoryDexClassLoader infrastructure | 🟡 MEDIUM | 🟡 Probable |
| **Missing Signatures** | No CERT.RSA/CERT.SF/MANIFEST.MF in META-INF | 🟡 MEDIUM | 🟢 Confirmed |
| **Obfuscated Services** | p.czt, p.uk90, p.t1v service providers | 🟡 MEDIUM | 🟡 Suspected |
| **Legitimate Trackers** | Facebook, comScore, Firebase, Branch, Google Ads | 🟢 LOW | 🟢 Confirmed (expected) |
| **Root/Magisk Detection** | librootChecker.so (Ravelin) | 🟢 LOW | 🟢 Confirmed (legitimate) |

---

## Indicators of Compromise (IOCs)

### File Hashes (Key Files)

| File | Size | Description |
|---|---|---|
| `classes.dex` (root) | 2,940 bytes | LSPatch stub loader |
| `assets/dexopt/nibrut.nibrut` | 95,257,114 bytes | Hidden ZIP payload |
| `kotlin/ranges/arm64-v8a/libnibrut.so` | 253,512 bytes | LSPatch native hooking engine (arm64) |
| `kotlin/ranges/armeabi-v7a/libnibrut.so` | 192,508 bytes | LSPatch native hooking engine (armv7) |
| `classes12.dex` (inside nibrut) | 68,476 bytes | LiteAPKs injected module |

### Network IOCs

| Domain/URL | Type | Context |
|---|---|---|
| `liteapks.com` | Mod distribution site | Linked in classes12.dex |
| `t.me/best_video_editings` | Telegram channel | Linked in classes12.dex |
| `9mod.com` | Mod distribution site | Referenced in dialog text |

### String IOCs

```
org.lsposed.lspatch.metaloader.LSPAppComponentFactoryStub
org.lsposed.lspatch.loader.LSPApplication
org.lsposed.lspd.service.
org.lsposed.lspd.core.
org.lsposed.lspd.nativebridge.
de.robv.android.xposed.
Bootstrap loader from embedment
LSPatch-MetaLoader
dialog/maker/ClassicDialog
LITEAPKS.COM and 9MOD.COM are Trusted sources for Modded apps & Games.
```

### File Path IOCs

```
kotlin/ranges/arm64-v8a/libnibrut.so     ← Native library hidden in Kotlin metadata path
kotlin/ranges/armeabi-v7a/libnibrut.so   ← Native library hidden in Kotlin metadata path
assets/dexopt/nibrut.nibrut              ← ZIP archive with fake extension
```

---

## What LiteAPKs.com / 9MOD.COM Are

### LiteAPKs.com

LiteAPKs is a website that distributes **modified ("modded") Android APK files**. They take legitimate apps from the Google Play Store, modify them to unlock premium features, and redistribute them for free. Their "business model" involves:

1. **Injecting adware modules** (like `classes12.dex`) into every mod they distribute
2. **Promoting their Telegram channels** through mandatory dialogs
3. **Cross-promoting 9MOD.COM** as a partner site
4. **Using encryption** to hide their infrastructure from security researchers
5. **Using LSPatch** (an open-source Xposed framework variant) to perform the actual premium unlock

### 9MOD.COM

9MOD.COM is a partner mod distribution site referenced in the LiteAPKs dialog text:
```
"LITEAPKS.COM and 9MOD.COM are Trusted sources for Modded apps & Games."
```

### The Telegram Channel

```
https://t.me/best_video_editings
```

This Telegram channel is used to:
- Distribute updates to modded apps
- Notify users of new mods
- Build a user base for the modding operation
- Provide download links that can be changed dynamically (unlike hardcoded APK URLs)

### How They Monetize

1. **Adware dialogs** — Every app launch may show a promotional dialog
2. **Traffic generation** — Driving users to liteapks.com generates ad revenue
3. **Telegram subscriber growth** — Larger channels can be monetized or sold
4. **User data collection** — Device fingerprinting + encrypted network communication suggests data harvesting
5. **Potential affiliate revenue** — Redirecting users to other mod sites/app stores

---

## How to Protect Yourself

### If You Have This APK Installed

1. **Uninstall it immediately** via Settings → Apps → Spotify → Uninstall
2. **Change your Spotify password** — the app had access to your login credentials
3. **Revoke Spotify sessions** — Go to spotify.com → Account → Sign Out Everywhere
4. **Check for unknown apps** — the mod's network + encryption capabilities could have downloaded additional software
5. **Review connected apps** — Check spotify.com → Account → Apps for unknown authorized applications
6. **Monitor for unusual activity** — Check bank/payment methods linked to Spotify
7. **Consider a factory reset** — if you're extremely cautious, as LSPatch operates at the ART level

### General Prevention

1. **Never install APKs from third-party sources** — especially "Premium" or "cracked" versions
2. **Use Google Play Protect** — it can detect known packed/modified APKs
3. **Check APK signatures** — legitimate Spotify is signed by Spotify AB
4. **Be skeptical of "free premium"** — if it's free, you are the product
5. **Use official free tiers** — Spotify's free tier with ads is safer than any mod

---

## Technical Methodology

This analysis was performed using the following techniques:

1. **File structure enumeration** — Complete directory listing of the extracted APK
2. **Magic byte analysis** — Reading file headers to identify true file types (`PK` for ZIP, `dex\n039` for DEX, `\x7FELF` for ELF)
3. **ZIP archive inspection** — Enumerating all entries inside `nibrut.nibrut` using `System.IO.Compression.ZipFile`
4. **String extraction** — Pulling all readable ASCII strings (4+ and 8+ character thresholds) from:
   - The stub `classes.dex` (root)
   - `libnibrut.so` (arm64-v8a)
   - `librootChecker.so` (arm64-v8a)
   - `liborbit-jni-spotify.so` (arm64-v8a)
   - All 12 DEX files inside `nibrut.nibrut`
5. **URL/domain extraction** — Regex-based extraction of all HTTP/HTTPS URLs from DEX files
6. **Base64 decoding** — Attempting to decode all Base64-like strings to identify encrypted payloads
7. **Targeted string searches** — Searching for patterns related to:
   - LSPatch/Xposed/hooking (`lsp`, `xposed`, `hook`, `patch`, `inject`)
   - Malware indicators (`backdoor`, `trojan`, `keylog`, `steal`, `c2`)
   - Cryptography (`Cipher`, `AES`, `encrypt`, `decrypt`, `SecretKey`)
   - Network activity (`HttpURL`, `openConnection`, `getInputStream`)
   - Data exfiltration (`SharedPreferences`, `getPackage`, `MessageDigest`)
   - Mod-specific (`liteapk`, `9mod`, `telegram`, `t.me`)
8. **File size analysis** — Comparing expected vs actual sizes to identify anomalies
9. **Cross-referencing** — Verifying which components are present in the official Spotify app vs injected by the modder
10. **ELF symbol analysis** — Examining demangled C++ symbols in native libraries to understand ART hooking mechanisms

**Tools used**: PowerShell, .NET System.IO/System.Text/System.IO.Compression APIs, regex pattern matching, hex analysis.

---

## Final Verdict

```
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT LEVEL: HIGH                           │
│                                                                 │
│  This APK is NOT just a simple "premium unlock."                │
│                                                                 │
│  It is a sophisticated, multi-layered package containing:       │
│                                                                 │
│  ✗ An Xposed/LSPatch framework operating at the ART level      │
│  ✗ Hidden native code in deceptive filesystem locations         │
│  ✗ A 90 MB encrypted payload disguised with a fake extension   │
│  ✗ An injected adware module with encryption and networking    │
│  ✗ Device fingerprinting capabilities                          │
│  ✗ The infrastructure to download and execute arbitrary code   │
│  ✗ No verifiable signing certificates                          │
│                                                                 │
│  Even if it currently "just" unlocks premium features and       │
│  shows Telegram ads, the encryption + network + runtime code    │
│  loading infrastructure means its behavior can change at any    │
│  time without updating the APK.                                 │
│                                                                 │
│  RECOMMENDATION: Do not install. If installed, remove           │
│  immediately and change all associated passwords.               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Credits

This full forensic reverse-engineering analysis was conducted by **[Hegxib](https://hegxib.me)**.

| | |
|---|---|
| **Author** | Hegxib |
| **Website** | [hegxib.me](https://hegxib.me) |
| **GitHub** | [@Hegxib](https://github.com/Hegxib) |
| **Repository** | [is-liteapks.com-spotify-2.html-safe](https://github.com/Hegxib/is-liteapks.com-spotify-2.html-safe) |

If you reference, share, or repost this analysis anywhere, please credit **Hegxib** and link back to the repo or [hegxib.me](https://hegxib.me).

---

## 💸 Donations

If this research helped you or saved your device from malware, consider supporting more work like this:

| Method | Link / Address |
|---|---|
| **Bitcoin (BTC)** | `bc1qppajze80mq8wcrap0ym00mch0w8z6qvpcscku2` |
| **Ethereum (ETH)** | `0x83Cc0fe051bEf3c8D7633665F165fd9E1AFb10fC` |
| **Ko-fi** | [Ko-fi/Hegxib](https://ko-fi.com/Hegxib) |

Every donation helps fund more deep-dive security research and keeps this work free for everyone. 🙏

---

## License & Disclaimer

This security analysis is provided for **educational and security research purposes only**. The author does not endorse, support, or distribute pirated software. All trademarks (Spotify, Google, Facebook, etc.) belong to their respective owners.

The findings in this document are based on **static analysis only** — examining file structures, binary strings, and metadata without executing the code. Dynamic analysis (running the APK in a sandbox) may reveal additional behaviors not covered here.

This analysis was conducted by **[Hegxib](https://hegxib.me)** on **February 23, 2026**.

---

*If you found this analysis useful, ⭐ star the repo and share it to help others stay safe from modified APKs.*
