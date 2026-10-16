#pragma once

#include <filesystem>
#include <fstream>
#include <unordered_set>

#include "Managers/DependencyManager.h"
#include "Managers/StructManager.h"
#include "Managers/MemberManager.h"
#include "Wrappers/StructWrapper.h"
#include "Wrappers/MemberWrappers.h"
#include "Wrappers/EnumWrapper.h"
#include "Managers/PackageManager.h"

#include "HashStringTable.h"
#include "Generator.h"

namespace fs = std::filesystem;

class CppGenerator
{
private:
    friend class CppGeneratorTest;
    friend class Generator;

public:
    /* Used by IDAMappingGenerator */
    struct ParamInfo
    {
        bool bIsOutPtr;
        bool bIsOutRef;
        bool bIsMoveParam;
        bool bIsRetParam;
        bool bIsConst;
        EPropertyFlags PropFlags;

        std::string Type;
        std::string Name;
    };

    /* Used by IDAMappingGenerator */
    struct FunctionInfo
    {
        bool bIsReturningVoid;
        EFunctionFlags FuncFlags = EFunctionFlags::None;

        std::string RetType;
        std::string FuncNameWithParams;

        std::vector<ParamInfo> UnrealFuncParams; // for unreal-functions only
    };

private:
    enum class EFileType
    {
        Classes,
        Structs,
        Parameters,
        Functions,

        NameCollisionsInl,

        BasicHpp,
        BasicCpp,

        UnrealContainers,
        UnicodeLib,

        PropertyFixup,
        SdkHpp,

        DebugAssertions,
    };

public:
    friend class CppGeneratorAccessor;

private:
    using StreamType = std::ofstream;

public:
    static inline PredefinedMemberLookupMapType PredefinedMembers;

    static inline std::string MainFolderName = "CppSDK";
    static inline std::string SubfolderName = "SDK";

    static inline fs::path MainFolder;
    static inline fs::path Subfolder;

private:
    static inline std::vector<PredefinedStruct> PredefinedStructs;

private:
    static std::string MakeMemberString(const std::string& Type, const std::string& Name, std::string&& Comment);
    static std::string MakeMemberStringWithoutName(const std::string& Type);

    static std::string GenerateBytePadding(const int32 Offset, const int32 PadSize, std::string&& Reason);
    static std::string GenerateBitPadding(uint8 UnderlayingSizeBytes, const uint8 PrevBitPropertyEndBit, const int32 Offset, const int32 PadSize, std::string&& Reason);

    static std::string GenerateMembers(const StructWrapper& Struct, const MemberManager& Members, int32 SuperSize, int32 SuperLastMemberEnd, int32 SuperAlign, int32 PackageIndex = -1);
    static FunctionInfo GenerateFunctionInfo(const FunctionWrapper& Func, const bool bAddExplicitThis = false);

    // return: In-header function declarations and inline functions
    static std::string GenerateSingleFunction(const FunctionWrapper& Func, const std::string& StructName, StreamType& FunctionFile, StreamType& ParamFile, StreamType& AssertionFile);
    static std::string GenerateFunctions(const StructWrapper& Struct, const MemberManager& Members, const std::string& StructName, StreamType& FunctionFile, StreamType& ParamFile, StreamType& AssertionFile);

    static void GenerateStruct(const StructWrapper& Struct, StreamType& StructFile, StreamType& FunctionFile, StreamType& ParamFile, StreamType& AssertionFile, int32 PackageIndex = -1, const std::string& StructNameOverride = std::string());

    static void GenerateEnum(const EnumWrapper& Enum, StreamType& StructFile);

private: /* utility functions */
    static std::string GetMemberTypeString(const PropertyWrapper& MemberWrapper, int32 PackageIndex = -1, bool bAllowForConstPtrMembers = false /* const USomeClass* Member; */);
    static std::string GetMemberTypeString(UEProperty Member, int32 PackageIndex = -1, bool bAllowForConstPtrMembers = false);
    static std::string GetMemberTypeStringWithoutConst(UEProperty Member, int32 PackageIndex = -1, bool* bOutIsUnknownProperty = nullptr);

    static std::string GetFunctionSignature(StructWrapper Func);

    static std::string GetStructPrefixedName(const StructWrapper& Struct);
    static std::string GetEnumPrefixedName(const EnumWrapper& Enum);
    static std::string GetEnumUnderlayingType(const EnumWrapper& Enm);
	static std::string GetEnumForcedSizeType(const EnumWrapper& Enm, const uint8_t PropertySize);

    static std::string GetAssertionMacroString(const std::string& PrefixedStructUniqueName);

    static std::string GetCycleFixupType(const StructWrapper& Struct, bool bIsForInheritance);

    /* [issue #562] Structs whose Pad_0 byte must be suppressed because a derived struct's first member is reflected at 0x0 (native layout applied empty-base optimisation). Populated by a full-graph pre-pass in Generate() before any struct is emitted. */
    static std::unordered_set<int32> StructsRequiringEmptyBase;

    /* [MSVC tail-slack fix] Bases whose aligned size exceeds their content end AND whose tail is entered
       by some derived's first member (below the base's aligned size, without StructManager's reuse flag
       having caught it -- the flag walk only covers the hardcoded StructInfoOverrides). These must keep
       compiler-owned tail slack; every other slackful base gets its slack covered by a real Pad member
       so MSVC cannot slurp a derived's leading Pad into it. Populated by the full-graph pre-pass in Generate(). */
    static std::unordered_set<int32> BasesNeedingTailSlack;

    static std::unordered_map<std::string, UEProperty> GetUnknownProperties();

private:
    static void GenerateEnumFwdDeclarations(StreamType& ClassOrStructFile, PackageInfoHandle Package, bool bIsClassFile);

private:
    static fs::path GetSDKTestScriptPath();

private:
    static void GenerateNameCollisionsInl(StreamType& NameCollisionsFile);
    static void GeneratePropertyFixupFile(StreamType& PropertyFixup);
    static void GenerateDebugAssertions(StreamType& AssertionStream);
	static void GenerateSDKTestScript(StreamType& TestScript);
    static void WriteFileHead(StreamType& File, PackageInfoHandle Package, EFileType Type, const std::string& CustomFileComment = "", const std::string& CustomIncludes = "");
    static void WriteFileEnd(StreamType& File, EFileType Type);

    static void GenerateSDKHeader(StreamType& SdkHpp);

    static void GenerateBasicFiles(StreamType& BasicH, StreamType& BasicCpp, StreamType& AssertionsFile);

    /*
    * Creates the UnrealContainers.hpp file (without allocation code) for the SDK. 
    * File contains the implementation of TArray, FString, TSparseArray, TSet, TMap and iterators for them
    *
    * See https://github.com/Fischsalat/UnrealContainers/blob/master/UnrealContainers/UnrealContainersNoAlloc.h 
    */
    static void GenerateUnrealContainers(StreamType& UEContainersHeader);

    /*
    * Creates the UtfN.hpp file for the SDK.
    *
    * See https://github.com/Fischsalat/UTF-N
    */
    static void GenerateUnicodeLib(StreamType& UnicodeLib);

public:
    static void Generate();

    static void InitPredefinedMembers();
    static void InitPredefinedFunctions();

public:
	static bool ExecuteSDKCompilationTestScript();
};