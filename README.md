
# vova-dumper

SDK generator for all Unreal Engine games — UE4.11 through UE5.8. Inject into a running
game and get a compile-clean, ABI-true C++ SDK plus `.usmap`, IDA, Dumpspace, Rizin and
radare2 mappings.

The generated CppSDK carries per-member `static_assert(offsetof(...))` checks
(`Assertions.inl`) — an SDK from vova-dumper proves its own layouts at compile time, so a
drifted offset surfaces as a build error instead of silent memory corruption in your tool.

## Output formats

- **CppSDK** — full C++ SDK with `Assertions.inl` offset verification
- **Mappings** — `.usmap` for UE4/UE5
- **IDA** — type headers (`.idmap` + `.h`)
- **Dumpspace** — JSON mappings
- **Rizin / radare2** — type headers with exact member offsets (explicit padding,
  dialect-correct bitfields)

## How to use

- Build (CMake, VS2022):
  ```
  cmake --preset vs2022
  cmake --build --preset vs2022-Release
  ```
  The dll lands in `out/build/vs2022/bin/Release/vova-dumper.dll`.
- Inject the dll into your target game.
- The SDK is generated into the path specified by `Settings::SDKGenerationPath`,
  by default `C:\vova-dumper`.
- **See [UsingTheSDK](UsingTheSDK.md) for a guide to get started, or to migrate from an old SDK.**

## Engine support and hardening

What vova-dumper handles that its lineage does not:

- **UE 5.7/5.8** — `FFieldClass` offsets are derived at runtime from the CastFlags anchor
  and validated against canonical property-class names; hardcoded offsets break on 5.7+
  (see upstream Dumper-7 issue #508).
- **ABI-true derived layouts** — graph-discriminated MSVC base-tail padding. Intruder
  deriveds (first member below `Super.GetSize()`) keep the compiler-owned slack they are
  compiled into; pad-led deriveds get explicit `Pad_*` members. Both families land every
  reflected member at its true offset — verified live: 102 failing layout asserts → 0.
- **Cyclic-dependency packages** — handled structurally via a pre-pass over the whole
  object graph instead of a hardcoded struct table.
- **Exact enum sizes** — the forced-size underlying type is emitted for IDA and Dumpspace,
  so byte-enums stop inflating layouts in those formats.
- **Robust output pipeline** — UTF-8 everywhere, `vova-dumper.ini` picked up next to the
  game exe, timestamped backups of previous outputs, duplicate-name diagnostics.
- **Depth-guarded generation** — runaway member-depth cases soft-fail with a report
  instead of crashing the game.
- **Manually-mapped injection safe** — `FName` comparison-index range guards stop
  corrupted-metadata reads from faulting inside the game's pool code.

Verified live on Hood Warfare 2 (UE 5.8.3-58210709): 15.1 MB WithProperties dump over 77k
objects, zero invalid names, and a full compile battery over the generated SDK —
`SDK.hpp`, `Assertions.inl`, and every `*_functions.cpp` TU — clean.

## Lineage

vova-dumper grew out of **Dumper-7 by Fischsalat**
(https://github.com/Encryqed/Dumper-7) and keeps its generator architecture — credit for
the original codebase belongs there. The project has since diverged into its own
generator; the engine support and hardening listed above are vova-dumper's own.

## Overriding Offsets

- ### Only override any offsets if the generator doesn't find them, or if they are incorrect
- All overrides are made in **Generator::InitEngineCore()** inside of **Generator.cpp**

- GObjects (see [GObjects-Layout](#overriding-gobjects-layout) too)
  ```cpp
  ObjectArray::Init(/*GObjectsOffset*/, /*ChunkSize*/, /*bIsChunked*/);
  ```
  ```cpp
  /* Make sure only to use types which exist in the sdk (eg. uint8, uint64) */
  InitObjectArrayDecryption([](void* ObjPtr) -> uint8* { return reinterpret_cast<uint8*>(uint64(ObjPtr) ^ 0x8375); });
  ```
- FName::AppendString
  - Forcing GNames:
    ```cpp
    FName::Init(/*bForceGNames*/); // Useful if the AppendString offset is wrong
    ```
  - Overriding the offset:
    ```cpp
    FName::Init(/*OverrideOffset, OverrideType=[AppendString, ToString, GNames], bIsNamePool*/);
    ```
- ProcessEvent
  ```cpp
  Off::InSDK::InitPE(/*PEIndex*/);
  ```
## Overriding GObjects-Layout
- Only add a new layout if GObjects isn't automatically found for your game.
- Layout overrides are at roughly line 30 of `ObjectArray.cpp`
- For UE4.11 to UE4.20 add the layout to `FFixedUObjectArrayLayouts`
- For UE4.21 and higher add the layout to `FChunkedFixedUObjectArrayLayouts`
- **Examples:**
  ```cpp
  FFixedUObjectArrayLayout // Default UE4.11 - UE4.20
  {
      .ObjectsOffset = 0x0,
      .MaxObjectsOffset = 0x8,
      .NumObjectsOffset = 0xC
  }
  ```
  ```cpp
  FChunkedFixedUObjectArrayLayout // Default UE4.21 and above
  {
      .ObjectsOffset = 0x00,
      .MaxElementsOffset = 0x10,
      .NumElementsOffset = 0x14,
      .MaxChunksOffset = 0x18,
      .NumChunksOffset = 0x1C,
  }
  ```

## Config File
You can optionally dynamically change settings through a `vova-dumper.ini` file, instead of modifying `Settings.h`.
- **Per-game**: Create `vova-dumper.ini` in the same directory as the game's exe file.
- **Global**: Create `vova-dumper.ini` under `C:\vova-dumper`.
- Profiles do not merge. In other words your global profile does not change the default settings.
  
- **SleepTimeout:**
  - If non-zero dump will start after a delay
  - Values under 1000 assumed to be in seconds, otherwise in milliseconds
  - If both SleepTimeout and DumpKey are set whichever occurs first will trigger the dump
- **DumpKey:** 
  - If non-zero dump will start upon key press
  - Value should be a hex or decimal integer corresponding to a [virtual keycode](https://learn.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes).
  - Hex integers should start with 0x.
- **SDKNamespaceName:**
  - Changes the namespace in the generated files.
- **SDKGenerationPath:**
  - Generate output at the specified path instead of `C:/vova-dumper`.
  - Paths are relative to game executable unless you use an absolute path including drive letter.
  - Use `..` to access parent directories. Do not include quotes.


### Example:
```ini
[Settings]
SleepTimeout=30
SDKNamespaceName=MyOwnSDKNamespace
DumpKey=0x77
SDKGenerationPath=./
```
- These settings would generate the SDK in the same folder as the game and would start after 30 seconds or upon pressing F8.

## Issues

If you have any issues using the Dumper, please create an Issue on this repository\
and explain the problem **in detail**.

- Should your game be crashing while dumping, attach Visual Studios' debugger to the game and inject the vova-dumper.dll in debug-configuration.
Then include screenshots of the exception causing the crash, a screenshot of the callstack, as well as the console output.

- For compiler-errors in the SDK (first verify you followed all of the steps from [UsingTheSDK](UsingTheSDK.md) correctly):
  1. Send screenshots of the errors in the error-window, make sure to select **`Build Only`**, not `Build + Intellisense`, as Intellisense often reports false positives.
  2. Also send a screenshot of the first error in the **Output**-window (NOT the error-window) and one of the code location causing that exact error.
  3. If you're able to fix the error (eg. missing padding in predefined struct, or incorrect use of macro name) please still report it in an issue with the fix included.
  4. If you're not able to resolve the issue yourself please upload the entire generated folder (not just CppSDK) somewhere and attach the link to your issue.

- Should your own dll-project crash, verify your code thoroughly to make sure the error actually lies within the generated SDK.
