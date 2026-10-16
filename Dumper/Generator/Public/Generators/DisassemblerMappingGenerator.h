#pragma once

#include "Wrappers/StructWrapper.h"
#include "Wrappers/EnumWrapper.h"
#include "Wrappers/MemberWrappers.h"

#include <sstream>
#include <string>
#include <vector>

#include "Unreal/ObjectArray.h"
#include "PredefinedMembers.h"
#include "Managers/PackageManager.h"
#include "Generator.h"

/*
* Which disassembler tool the emitted type-header and loader-script are written for.
* The dialects differ in:
*   - bitfield emission (Rizin: real C bitfields on bare primitive types,
*     Radare2: collapsed flag-bytes, since r2's C parser rejects every bitfield spelling)
*   - loader-script flag syntax and header-path quoting
*/
enum class EDisassemblerDialect
{
	Rizin,
	Radare2
};

/*
* Shared emission logic behind RizinMappingGenerator and Radare2MappingGenerator.
*
* Writes into the given folder:
*   - "<GameVersion>-<GameName>_types.h": portable-C type library (no #pragma once, no block
*     comments, no MSVC types, byte-exact layouts via explicit padding members)
*   - "load.rz" / "load.r2": loader script importing the header and flagging the global symbols
*     (GObjects, GNames, GWorld, ProcessEvent, AppendString, GetNameEntryFromName)
*/
class DisassemblerMappingEmitter
{
public:
	/* Result of resolving a property/predefined-member to a portable-C type declaration. */
	struct FResolvedMemberType
	{
		/* Base type, e.g. "int", "struct FVector", "void". Pointers are flagged via bIsPtr. */
		std::string Type;

		/* Emit as '<Type>*'. */
		bool bIsPtr = false;

		/* Extra note appended to the member's // comment (enum name, self-pointer info). */
		std::string ExtraComment;

		/*
		* Fallback for unknown property types larger than 8 bytes: emit 'unsigned char Name[0xSize];'
		* instead of a scalar, so the declared byte-span matches the property size.
		*/
		bool bForceByteSpan = false;
	};

public:
	static void Generate(const fs::path& OutFolder, EDisassemblerDialect Dialect);

private:
	/* Tracks byte offsets while writing one struct body; defined in the cpp (dialect-aware padding/bitfields). */
	class FStructLayoutEmitter;

	static std::string GetStructPrefixedName(const StructWrapper& Struct);
	static std::string GetEnumPrefixedName(const EnumWrapper& Enum);

	static std::string ConvertPredefinedTypeForDisasm(std::string Type, bool& OutIsPtr);

	static FResolvedMemberType ResolveMemberType(const PropertyWrapper& Member, const std::string& SelfStructName);
	static FResolvedMemberType ResolvePropertyType(UEProperty Property, const std::string& SelfStructName);

	static std::vector<PredefinedStruct> BuildPredefinedTypes();

	static void EmitForwardDeclarations(std::stringstream& Out, const std::vector<PackageInfoHandle>& Packages);
	static void EmitEnum(std::stringstream& Out, const EnumWrapper& Enum);
	static void EmitStruct(std::stringstream& Out, const StructWrapper& Struct, EDisassemblerDialect Dialect);

	static std::vector<PackageInfoHandle> CollectPackagesInDependencyOrder();

	static uint64 GetPreferredImageBase();
	static void WriteLoaderScript(const fs::path& OutFolder, const fs::path& HeaderFile, EDisassemblerDialect Dialect);
};

class RizinMappingGenerator
{
public:
	static inline PredefinedMemberLookupMapType PredefinedMembers;

	static inline std::string MainFolderName = "RizinMappings";
	static inline std::string SubfolderName = "";

	static inline fs::path MainFolder;
	static inline fs::path Subfolder;

public:
	static void Generate();

	static void InitPredefinedMembers();
	static void InitPredefinedFunctions() {}
};

class Radare2MappingGenerator
{
public:
	static inline PredefinedMemberLookupMapType PredefinedMembers;

	static inline std::string MainFolderName = "Radare2Mappings";
	static inline std::string SubfolderName = "";

	static inline fs::path MainFolder;
	static inline fs::path Subfolder;

public:
	static void Generate();

	static void InitPredefinedMembers();
	static void InitPredefinedFunctions() {}
};
