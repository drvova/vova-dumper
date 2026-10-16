#include "Generators/DisassemblerMappingGenerator.h"
#include "SharedPredefinedMembers.h"
#include "TmpUtils.h"

#include "Managers/PackageManager.h"
#include "Platform.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <fstream>
#include <functional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

/* ------------------------------------------------------------------------------------------------
 * Portable-C helpers
 * ------------------------------------------------------------------------------------------------ */

static std::string GetPortableTypeFromSize(uint8 Size)
{
	/* Portable C only: rizin silently maps MSVC types like __int64 to unknown_t. */
	switch (Size)
	{
	case 1:
		return "unsigned char";
	case 2:
		return "unsigned short";
	case 4:
		return "unsigned int";
	case 8:
		return "unsigned long long";
	default:
		return "unsigned char";
	}
}

/* Base type for bitfield members. Must be a BARE primitive: rizin rejects sized_specifier bitfields ("unsigned char b : 1;" -> "Struct bitfield cannot contain non-primitive bitfield!"). */
static std::string GetBitfieldBaseType(int32 UnderlyingSizeBytes)
{
	switch (UnderlyingSizeBytes)
	{
	case 1:
		return "char";
	case 2:
		return "short";
	case 4:
		return "int";
	case 8:
		return "long long";
	default:
		return "char";
	}
}

std::string DisassemblerMappingEmitter::GetStructPrefixedName(const StructWrapper& Struct)
{
	if (Struct.IsFunction())
		return Struct.GetUnrealStruct().GetOuter().GetValidName() + "_" + Struct.GetName();

	auto [ValidName, bIsUnique] = Struct.GetUniqueName();

	if (bIsUnique) [[likely]]
		return ValidName;

	return PackageManager::GetName(Struct.GetUnrealStruct().GetPackageIndex()) + "_" + ValidName;
}

std::string DisassemblerMappingEmitter::GetEnumPrefixedName(const EnumWrapper& Enum)
{
	auto [ValidName, bIsUnique] = Enum.GetUniqueName();

	if (bIsUnique) [[likely]]
		return ValidName;

	return PackageManager::GetName(Enum.GetUnrealEnum().GetPackageIndex()) + "_" + ValidName;
}

static std::string TrimTrailingSpaces(std::string Type)
{
	while (!Type.empty() && Type.back() == ' ')
		Type.pop_back();

	return Type;
}

/*
* Mirrors IDAMappingGenerator::ConvertPredefinedTypeForIDA, but converts to portable C.
* Converts predefined-member type strings ("int32", "wchar_t*", "struct FField*", "TArray<int>", ...) to
* types both rizin and radare2 parse, returning base-type + pointer flag.
* All trailing '*' are stripped and re-appended after conversion, so "void**" never becomes "struct void*".
*/
std::string DisassemblerMappingEmitter::ConvertPredefinedTypeForDisasm(std::string Type, bool& OutIsPtr)
{
	OutIsPtr = false;

	int32 PointerLevels = 0;
	while (!Type.empty() && Type.back() == '*')
	{
		Type.pop_back();
		Type = TrimTrailingSpaces(std::move(Type));
		PointerLevels++;
	}

	OutIsPtr = (PointerLevels > 0);

	// Replace "class " with "struct " (we only ever emit struct/union tags).
	if (Type.starts_with("class "))
		Type.replace(0, 6, "struct ");

	// Strip template arguments ("TArray<int>" -> "TArray"); disassemblers have no templates.
	const auto AngleBracket = Type.find('<');
	if (AngleBracket != std::string::npos)
	{
		Type = Type.substr(0, AngleBracket);
		Type = TrimTrailingSpaces(std::move(Type));
	}

	// Fixed-width scalars -> portable C
	if (Type == "uint8")
		Type = "unsigned char";
	else if (Type == "int8")
		Type = "char";
	else if (Type == "uint16")
		Type = "unsigned short";
	else if (Type == "int16")
		Type = "short";
	else if (Type == "int32")
		Type = "int";
	else if (Type == "uint32")
		Type = "unsigned int";
	else if (Type == "int64")
		Type = "long long";
	else if (Type == "uint64")
		Type = "unsigned long long";
	// wchar_t is 2 bytes on Windows; map it, some type databases don't know it.
	else if (Type == "wchar_t")
		Type = "unsigned short";
	// Internal engine flag-enums are not defined in this header; emit them at their size.
	else if (Type == "EObjectFlags" || Type == "EClassCastFlags" || Type == "EFunctionFlags")
		Type = "unsigned int";
	else
	{
		// Strip enum prefixes; enum-backed members are laid out by their underlying integer, not the tag.
		if (Type.starts_with("enum class "))
			Type = Type.substr(11);
		else if (Type.starts_with("enum "))
			Type = Type.substr(5);

		Type = TrimTrailingSpaces(std::move(Type));

		// Everything else that isn't a builtin is a struct tag reference.
		if (!Type.starts_with("struct ") && !Type.starts_with("union ") &&
			Type != "void" && Type != "float" && Type != "double" && Type != "bool" && Type != "char" &&
			Type != "unsigned char" && Type != "short" && Type != "unsigned short" &&
			Type != "int" && Type != "unsigned int" &&
			Type != "long long" && Type != "unsigned long long")
		{
			Type = "struct " + Type;
		}
	}

	// The emitter appends one '*' for OutIsPtr; re-append any additional levels here.
	if (PointerLevels > 1)
		Type += std::string(PointerLevels - 1, '*');

	return Type;
}

/* ------------------------------------------------------------------------------------------------
 * Property -> portable-C type resolution
 * ------------------------------------------------------------------------------------------------ */

DisassemblerMappingEmitter::FResolvedMemberType DisassemblerMappingEmitter::ResolvePropertyType(UEProperty Property, const std::string& SelfStructName)
{
	FResolvedMemberType Result;

	auto [Class, FieldClass] = Property.GetClass();
	EClassCastFlags Flags = Class ? Class.GetCastFlags() : FieldClass.GetCastFlags();

	if (Flags & EClassCastFlags::ByteProperty)
	{
		// UE byte-enums are 1 byte; 'enum X : unsigned char' kills both tools' parsers,
		// so the member is laid out as plain 'unsigned char' and the enum name goes into the comment.
		Result.Type = "unsigned char";

		if (UEEnum Enum = Property.Cast<UEByteProperty>().GetEnum())
			Result.ExtraComment = "enum " + GetEnumPrefixedName(EnumWrapper(Enum));
	}
	else if (Flags & EClassCastFlags::UInt16Property)
	{
		Result.Type = "unsigned short";
	}
	else if (Flags & EClassCastFlags::UInt32Property)
	{
		Result.Type = "unsigned int";
	}
	else if (Flags & EClassCastFlags::UInt64Property)
	{
		Result.Type = "unsigned long long";
	}
	else if (Flags & EClassCastFlags::Int8Property)
	{
		Result.Type = "char";
	}
	else if (Flags & EClassCastFlags::Int16Property)
	{
		Result.Type = "short";
	}
	else if (Flags & EClassCastFlags::IntProperty)
	{
		Result.Type = "int";
	}
	else if (Flags & EClassCastFlags::Int64Property)
	{
		Result.Type = "long long";
	}
	else if (Flags & EClassCastFlags::FloatProperty)
	{
		Result.Type = "float";
	}
	else if (Flags & EClassCastFlags::DoubleProperty)
	{
		Result.Type = "double";
	}
	else if (Flags & EClassCastFlags::ClassProperty)
	{
		Result.bIsPtr = true;
		Result.Type = "struct UClass";
	}
	else if (Flags & EClassCastFlags::NameProperty)
	{
		Result.Type = "struct FName";
	}
	else if (Flags & EClassCastFlags::StrProperty)
	{
		Result.Type = "struct FString";
	}
	else if (Flags & EClassCastFlags::TextProperty)
	{
		Result.Type = "struct FText";
	}
	else if (Flags & EClassCastFlags::BoolProperty)
	{
		Result.Type = Property.Cast<UEBoolProperty>().IsNativeBool() ? "bool" : GetPortableTypeFromSize(static_cast<uint8>(Property.GetSize()));
	}
	else if (Flags & EClassCastFlags::StructProperty)
	{
		const StructWrapper& UnderlayingStruct = Property.Cast<UEStructProperty>().GetUnderlayingStruct();
		Result.Type = std::format("struct {}", GetStructPrefixedName(UnderlayingStruct));
	}
	else if (Flags & EClassCastFlags::ArrayProperty)
	{
		Result.Type = "struct TArray";
	}
	else if (Flags & EClassCastFlags::WeakObjectProperty)
	{
		Result.Type = "struct TWeakObjectPtr";
	}
	else if (Flags & EClassCastFlags::LazyObjectProperty)
	{
		Result.Type = "struct TLazyObjectPtr";
	}
	else if (Flags & EClassCastFlags::SoftClassProperty)
	{
		Result.Type = "struct TSoftClassPtr";
	}
	else if (Flags & EClassCastFlags::SoftObjectProperty)
	{
		Result.Type = "struct TSoftObjectPtr";
	}
	else if (Flags & EClassCastFlags::ObjectProperty)
	{
		Result.bIsPtr = true;

		if (UEClass PropertyClass = Property.Cast<UEObjectProperty>().GetPropertyClass())
			Result.Type = std::format("struct {}", GetStructPrefixedName(PropertyClass));
		else
			Result.Type = "struct UObject";
	}
	else if (Settings::EngineCore::bEnableEncryptedObjectPropertySupport && (Flags & EClassCastFlags::ObjectPropertyBase))
	{
		Result.Type = "struct TEncryptedObjPtr";
	}
	else if (Flags & EClassCastFlags::MapProperty)
	{
		Result.Type = "struct TMap";
	}
	else if (Flags & EClassCastFlags::SetProperty)
	{
		Result.Type = "struct TSet";
	}
	else if (Flags & EClassCastFlags::EnumProperty)
	{
		if (UEEnum Enum = Property.Cast<UEEnumProperty>().GetEnum())
		{
			// Underlying integer carries the layout (see byte-enum note above).
			const FResolvedMemberType Underlying = ResolvePropertyType(Property.Cast<UEEnumProperty>().GetUnderlayingProperty(), SelfStructName);

			Result.Type = Underlying.Type;
			Result.bIsPtr = Underlying.bIsPtr;
			Result.bForceByteSpan = Underlying.bForceByteSpan;
			Result.ExtraComment = "enum " + GetEnumPrefixedName(EnumWrapper(Enum));
		}
		else
		{
			// Fallback: use underlying property's integer type
			return ResolvePropertyType(Property.Cast<UEEnumProperty>().GetUnderlayingProperty(), SelfStructName);
		}
	}
	else if (Flags & EClassCastFlags::InterfaceProperty)
	{
		Result.Type = "struct TScriptInterface";
	}
	else if (Flags & EClassCastFlags::DelegateProperty)
	{
		Result.Type = "struct FScriptDelegate";
	}
	else if (Flags & EClassCastFlags::MulticastInlineDelegateProperty)
	{
		Result.Type = "struct FMulticastInlineDelegate";
	}
	else if (Flags & EClassCastFlags::FieldPathProperty)
	{
		if (Settings::Internal::bIsObjPtrInsteadOfFieldPathProperty)
		{
			Result.bIsPtr = true;

			if (UEClass PropertyClass = Property.Cast<UEObjectProperty>().GetPropertyClass())
				Result.Type = std::format("struct {}", GetStructPrefixedName(PropertyClass));
			else
				Result.Type = "struct UObject";
		}
		else
		{
			Result.Type = "struct TFieldPath";
		}
	}
	else if (Flags & EClassCastFlags::OptionalProperty)
	{
		Result.Type = "struct TOptional";
	}
	else if (Flags & EClassCastFlags::Utf8StrProperty || Flags & EClassCastFlags::AnsiStrProperty)
	{
		Result.Type = "struct FUtf8String";
	}
	else
	{
		// Unknown property kind: lay it out at its size with unsigned scalars / a byte-span fallback.
		const int32 Size = Property.GetSize();

		Result.Type = GetPortableTypeFromSize(static_cast<uint8>(Size));
		Result.bForceByteSpan = (Size != 1 && Size != 2 && Size != 4 && Size != 8);

		if (Result.bForceByteSpan)
			Result.Type = "unsigned char";
	}

	/*
	* Self-referential pointers ('struct Foo* Bar;' inside 'struct Foo { ... }') size as 0 in rizin
	* and as 4 bytes in radare2's embedded-struct view, corrupting every later member.
	* Emit 'void*' (always native pointer size) and keep the real type in the comment.
	*/
	if (Result.bIsPtr && Result.Type == "struct " + SelfStructName)
	{
		Result.ExtraComment = std::format("self-pointer, actual type {}*", Result.Type);
		Result.Type = "void";
	}

	return Result;
}

DisassemblerMappingEmitter::FResolvedMemberType DisassemblerMappingEmitter::ResolveMemberType(const PropertyWrapper& Member, const std::string& SelfStructName)
{
	if (!Member.IsUnrealProperty())
	{
		FResolvedMemberType Result;
		bool bIsPtr = false;

		Result.Type = ConvertPredefinedTypeForDisasm(Member.GetType(), bIsPtr);
		Result.bIsPtr = bIsPtr;

		return Result;
	}

	return ResolvePropertyType(Member.GetUnrealProperty(), SelfStructName);
}

/* ------------------------------------------------------------------------------------------------
 * Struct body emission (offsets, padding, bitfields)
 * ------------------------------------------------------------------------------------------------ */

class DisassemblerMappingEmitter::FStructLayoutEmitter
{
private:
	std::stringstream& Out;
	const EDisassemblerDialect Dialect;
	const bool bIsUnion;

	/* Exclusive end of everything already written (max member end, mirrors CppGenerator::GenerateMembers). */
	int32 PrevPropertyEnd = 0;

	/* Rizin bitfield state (previous bitfield group). */
	bool bLastWasBitField = false;
	int32 PrevBitPropertyOffset = 0;
	int32 PrevBitPropertyEnd = 0;
	int32 PrevBitPropertySize = 1;
	uint32 PrevBitPropertyEndBit = 0;
	uint32 PrevNumBitsInUnderlyingType = 0x8;

	/* Radare2 collapsed flag-byte state (one pending 'unsigned char' per bitfield byte). */
	int32 PendingOffset = -1;
	int32 PendingEnd = 0;
	std::string PendingName;
	std::string PendingComment;

public:
	FStructLayoutEmitter(std::stringstream& InOut, EDisassemblerDialect InDialect, bool bInIsUnion)
		: Out(InOut), Dialect(InDialect), bIsUnion(bInIsUnion)
	{
	}

public:
	void EmitMember(const PropertyWrapper& Member, const std::string& SelfStructName)
	{
		// Static and zero-sized members don't contribute layout; unnamed members are invalid C.
		if (Member.IsStatic() || Member.IsZeroSizedMember())
			return;

		const int32 MemberOffset = Member.GetOffset();
		const int32 MemberSize = Member.GetSize();

		if (MemberOffset < 0 || MemberSize <= 0)
			return;

		if (Member.IsBitField())
		{
			/*
			* Rizin only accepts bitfields on bare primitive types, and among those only 'char' (1-byte
			* unit, verified bit-exact) and 'int' (4-byte unit, verified bit-exact) parse; 'short',
			* 'long long' and every 'unsigned ...' spelling error out with
			* "Struct bitfield cannot contain non-primitive bitfield!" and abort the whole header.
			* All other bitfield sizes collapse into a flag-byte (which is valid C everywhere).
			*/
			const bool bUseNativeBitFields = (Dialect == EDisassemblerDialect::Rizin) && (MemberSize == 1 || MemberSize == 4);

			if (bUseNativeBitFields)
				EmitBitFieldNative(Member, MemberOffset, MemberSize);
			else
				EmitBitFieldCollapsed(Member, MemberOffset, MemberSize);

			return;
		}

		/* Regular member: flush any pending collapsed flag-byte first (Radare2 dialect). */
		FlushPendingGroup();

		const FResolvedMemberType Info = DisassemblerMappingEmitter::ResolveMemberType(Member, SelfStructName);

		std::string NameDecl = Member.GetName();
		const int32 ArrayDim = (std::max)(Member.GetArrayDim(), 1);

		if (Info.bForceByteSpan)
		{
			/* Unknown oversized property: unsigned char Name[0xSize * ArrayDim]; */
			NameDecl += std::format("[0x{:X}]", MemberSize * ArrayDim);
		}
		else if (ArrayDim > 1)
		{
			NameDecl += std::format("[0x{:X}]", ArrayDim);
		}

		const std::string Comment = MakeComment(Member, MemberOffset, MemberSize, Info.ExtraComment);

		EmitTypedMember(Info.Type, Info.bIsPtr, NameDecl, MemberOffset, MemberSize * ArrayDim, Comment);
	}

	void Finish(int32 StructSize)
	{
		FlushPendingGroup();

		/* Trailing padding to the struct's (aligned) size, so tool-side sizeof matches the SDK. */
		if (StructSize > PrevPropertyEnd)
			EmitBytePad(PrevPropertyEnd, StructSize - PrevPropertyEnd);
	}

private:
	static std::string MakeComment(const PropertyWrapper& Member, int32 Offset, int32 Size, const std::string& ExtraComment)
	{
		std::string Comment = std::format("// 0x{:04X}(0x{:04X})({})", Offset, Size, Member.GetFlagsOrCustomComment());

		if (!ExtraComment.empty())
			Comment += std::format(" [{}]", ExtraComment);

		return Comment;
	}

	/* Writes '<Type><ptr> <NameDecl>; <Comment>' after filling any gap with an explicit pad member. */
	void EmitTypedMember(const std::string& Type, bool bIsPtr, const std::string& NameDecl, int32 Offset, int32 DeclaredSize, const std::string& Comment)
	{
		if (!bIsUnion && Offset > PrevPropertyEnd)
			EmitBytePad(PrevPropertyEnd, Offset - PrevPropertyEnd);

		Out << "\t" << Type << (bIsPtr ? "*" : "") << " " << NameDecl << "; " << Comment << "\n";

		PrevPropertyEnd = (std::max)(PrevPropertyEnd, Offset + DeclaredSize);
		bLastWasBitField = false;
	}

	void EmitBytePad(int32 Offset, int32 Size)
	{
		if (Size <= 0)
			return;

		Out << "\tunsigned char " << std::format("Pad_{:X}[0x{:X}]", Offset, Size)
			<< "; " << std::format("// 0x{:04X}(0x{:04X})(Fixing Size After Last Property [ vova-dumper ])", Offset, Size) << "\n";
	}

	/* Rizin dialect: real C bitfields on bare primitive types (verified round-trip exact). */
	void EmitBitFieldNative(const PropertyWrapper& Member, int32 MemberOffset, int32 MemberSize)
	{
		const uint8 BitFieldIndex = Member.GetBitIndex();
		const uint8 BitCount = Member.GetBitCount();
		const int32 CurrentPropertyEnd = MemberOffset + MemberSize;

		const std::string BaseType = GetBitfieldBaseType(MemberSize);

		if (!bIsUnion)
		{
			/* Padding between two bitfields at different byte-offsets: fill the rest of the old byte. */
			if (CurrentPropertyEnd > PrevPropertyEnd && bLastWasBitField && PrevBitPropertyEndBit < PrevNumBitsInUnderlyingType)
			{
				const uint32 FillBits = PrevNumBitsInUnderlyingType - PrevBitPropertyEndBit;

				Out << "\t" << GetBitfieldBaseType(PrevBitPropertySize) << " "
					<< std::format("BitPad_{:X}_{:X} : {};", PrevBitPropertyOffset, PrevBitPropertyEndBit, FillBits)
					<< " " << std::format("// 0x{:04X}(0x{:02X})(Fixing Bit-Field Size For New Byte [ vova-dumper ])", PrevBitPropertyOffset, FillBits) << "\n";
			}

			if (PrevBitPropertyEnd < MemberOffset)
				PrevBitPropertyEndBit = 0x0;

			/* Padding between bits of the same byte. */
			if (PrevBitPropertyEndBit < BitFieldIndex)
			{
				const uint32 GapBits = BitFieldIndex - PrevBitPropertyEndBit;

				Out << "\t" << BaseType << " "
					<< std::format("BitPad_{:X}_{:X} : {};", MemberOffset, PrevBitPropertyEndBit, GapBits)
					<< " " << std::format("// 0x{:04X}(0x{:02X})(Fixing Bit-Field Size Between Bits [ vova-dumper ])", MemberOffset, GapBits) << "\n";

				PrevBitPropertyEndBit = BitFieldIndex;
			}
		}

		Out << "\t" << BaseType << " " << Member.GetName() << " : " << static_cast<uint32>(BitCount) << "; "
			<< MakeComment(Member, MemberOffset, MemberSize, "") << "\n";

		PrevBitPropertyOffset = MemberOffset;
		PrevBitPropertySize = MemberSize;
		PrevBitPropertyEndBit = static_cast<uint32>(BitFieldIndex) + BitCount;
		PrevNumBitsInUnderlyingType = static_cast<uint32>(MemberSize) * 0x8;
		PrevBitPropertyEnd = CurrentPropertyEnd;
		PrevPropertyEnd = (std::max)(PrevPropertyEnd, CurrentPropertyEnd);
		bLastWasBitField = true;
	}

	/* Radare2 dialect: r2 rejects every bitfield spelling and aborts the whole file; collapse each
	 * bitfield byte into one 'unsigned char' with the per-flag bit layout kept in the comment. */
	void EmitBitFieldCollapsed(const PropertyWrapper& Member, int32 MemberOffset, int32 MemberSize)
	{
		const int32 CurrentPropertyEnd = MemberOffset + MemberSize;

		if (PendingOffset >= 0 && PendingOffset != MemberOffset)
			FlushPendingGroup();

		const uint8 BitFieldIndex = Member.GetBitIndex();
		const uint8 BitCount = Member.GetBitCount();

		if (PendingOffset < 0)
		{
			PendingOffset = MemberOffset;
			PendingEnd = CurrentPropertyEnd;
			PendingName = Member.GetName();
			PendingComment = std::format("{}:{}@bit{}", Member.GetName(), BitCount, BitFieldIndex);
		}
		else
		{
			PendingEnd = (std::max)(PendingEnd, CurrentPropertyEnd);
			PendingComment += std::format(", {}:{}@bit{}", Member.GetName(), BitCount, BitFieldIndex);
		}
	}

	void FlushPendingGroup()
	{
		if (PendingOffset < 0)
			return;

		const int32 Span = PendingEnd - PendingOffset;

		std::string NameDecl = PendingName;
		if (Span > 1)
			NameDecl += std::format("[0x{:X}]", Span);

		const std::string Comment = std::format("// 0x{:04X}(0x{:04X})(bitfields: {})", PendingOffset, Span, PendingComment);

		EmitTypedMember("unsigned char", false, NameDecl, PendingOffset, Span, Comment);

		PendingOffset = -1;
		PendingEnd = 0;
		PendingName.clear();
		PendingComment.clear();
	}
};

/* ------------------------------------------------------------------------------------------------
 * Struct / enum / forward-declaration emission
 * ------------------------------------------------------------------------------------------------ */

void DisassemblerMappingEmitter::EmitStruct(std::stringstream& Out, const StructWrapper& Struct, EDisassemblerDialect Dialect)
{
	/* An index can resolve to a purged GUObjectArray slot in the live game -> empty wrapper,
	 * and every accessor below (GetSuper/GetSize/GetMembers) would dereference null. */
	if (!Struct.IsValid())
		return;

	const std::string StructName = GetStructPrefixedName(Struct);
	const bool bIsUnion = Struct.IsUnion();

	/*
	* Inheritance doesn't exist in C: flatten the super chain (root first). Every member carries its
	* absolute Unreal offset and all gaps become explicit padding, so the layout stays byte-exact
	* without relying on base-class sizeof/alignment interaction (incl. reused super trailing padding).
	*/
	std::vector<StructWrapper> Chain;
	Chain.push_back(Struct);

	if (Struct.IsUnrealStruct())
	{
		/* StructWrapper has no copy-assignment (const members); walk up recursively. */
		std::function<void(const StructWrapper&, int32)> WalkSuperChain = [&](const StructWrapper& Current, int32 Depth) -> void
		{
			if (Depth >= 0x20)
				return;

			const StructWrapper Super = Current.GetSuper();

			if (!Super.IsValid())
				return;

			Chain.push_back(Super);

			if (Super.IsUnrealStruct())
				WalkSuperChain(Super, Depth + 1);
		};

		WalkSuperChain(Struct, 0);
	}

	Out << (bIsUnion ? "union " : "struct ") << StructName << "\n{\n";

	{
		FStructLayoutEmitter Layout(Out, Dialect, bIsUnion);

		for (auto It = Chain.rbegin(); It != Chain.rend(); ++It)
		{
			MemberManager Members = It->GetMembers();

			for (const PropertyWrapper& Member : Members.IterateMembers())
				Layout.EmitMember(Member, StructName);
		}

		Layout.Finish(Struct.GetSize());
	}

	Out << "};\n";
}

void DisassemblerMappingEmitter::EmitEnum(std::stringstream& Out, const EnumWrapper& Enum)
{
	if (!Enum.IsValid())
		return;

	Out << "enum " << GetEnumPrefixedName(Enum) << "\n{\n";

	for (const EnumCollisionInfo& Member : Enum.GetMembers())
		Out << "\t" << Member.GetUniqueName() << " = " << static_cast<int64_t>(Member.GetValue()) << ",\n";

	Out << "};\n";
}

void DisassemblerMappingEmitter::EmitForwardDeclarations(std::stringstream& Out, const std::vector<PackageInfoHandle>& Packages)
{
	/* Predefined types first: they reference each other by pointer before their definitions (FField* ...). */
	std::unordered_set<std::string> EmittedNames;

	auto EmitFwd = [&Out, &EmittedNames](const std::string& Name, bool bIsUnion) -> void
	{
		if (!EmittedNames.insert(Name).second)
			return;

		Out << (bIsUnion ? "union " : "struct ") << Name << ";\n";
	};

	for (const PredefinedStruct& Predef : BuildPredefinedTypes())
		EmitFwd(Predef.UniqueName, false);

	for (const PackageInfoHandle& Package : Packages)
	{
		DependencyManager::OnVisitCallbackType Visit = [&](int32 Index) -> void
		{
			const StructWrapper Struct(ObjectArray::GetByIndex<UEStruct>(Index));

			if (!Struct.IsValid())
				return;

			EmitFwd(GetStructPrefixedName(Struct), Struct.IsUnion());
		};

		if (Package.HasStructs())
			Package.GetSortedStructs().VisitAllNodesWithCallback(Visit);

		if (Package.HasClasses())
			Package.GetSortedClasses().VisitAllNodesWithCallback(Visit);
	}

	Out << "\n";
}

/* ------------------------------------------------------------------------------------------------
 * Predefined types (mirrors IDAMappingGenerator::GeneratePredefinedTypes' table)
 * ------------------------------------------------------------------------------------------------ */

#define DISASM_MEMBER_AT(MemberType, NameStr, OffsetExpr, SizeExpr, AlignExpr) \
	PredefinedMember{ \
		.Type = MemberType, .Name = NameStr, \
		.Offset = static_cast<int32>(OffsetExpr), \
		.Size = static_cast<int32>(SizeExpr), \
		.ArrayDim = 1, \
		.Alignment = static_cast<int32>(AlignExpr), \
		.bIsStatic = false, .bIsZeroSizeMember = false, .bIsBitField = false, .BitIndex = 0xFF \
	}

std::vector<PredefinedStruct> DisassemblerMappingEmitter::BuildPredefinedTypes()
{
	const int32 PtrSize = sizeof(void*);
	const int32 FNameSize = Off::InSDK::Name::FNameSize;
	const int32 FWeakObjectPtrSize = 0x08; // always two int32s

	std::vector<PredefinedStruct> Types;
	Types.reserve(32);

	auto AddPredef = [&](const char* Name, int32 Size, int32 Align) -> PredefinedStruct&
	{
		return Types.emplace_back(PredefinedStruct{
			.UniqueName = Name, .Size = Size, .Alignment = Align,
			.bUseExplictAlignment = false, .bIsFinal = true, .bIsClass = false, .bIsUnion = false, .Super = nullptr
		});
	};

	// TArray<T>: { T* Data; int32 NumElements; int32 MaxElements; }
	{
		PredefinedStruct& T = AddPredef("TArray", sizeof(TArray<int>), alignof(TArray<int>));
		T.Properties = {
			DISASM_MEMBER_AT("void*", "Data",        0,                              PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32", "NumElements", PtrSize,                        sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32", "MaxElements", PtrSize + (int32)sizeof(int32), sizeof(int32), alignof(int32)),
		};
	}

	// FString = TArray<wchar_t>
	{
		PredefinedStruct& T = AddPredef("FString", sizeof(TArray<int>), alignof(TArray<int>));
		T.Properties = {
			DISASM_MEMBER_AT("wchar_t*", "Data",        0,                              PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32",    "NumElements", PtrSize,                        sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32",    "MaxElements", PtrSize + (int32)sizeof(int32), sizeof(int32), alignof(int32)),
		};
	}

	// FUtf8String = TArray<char>
	{
		PredefinedStruct& T = AddPredef("FUtf8String", sizeof(TArray<int>), alignof(TArray<int>));
		T.Properties = {
			DISASM_MEMBER_AT("char*", "Data",        0,                              PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32", "NumElements", PtrSize,                        sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32", "MaxElements", PtrSize + (int32)sizeof(int32), sizeof(int32), alignof(int32)),
		};
	}

	// FName: layout depends on FNameSize (runtime)
	{
		PredefinedStruct& T = AddPredef("FName", FNameSize, alignof(int32));
		T.Properties.push_back(DISASM_MEMBER_AT("int32", "ComparisonIndex", 0, sizeof(int32), alignof(int32)));

		if (FNameSize >= (int32)(sizeof(int32) * 2))
			T.Properties.push_back(DISASM_MEMBER_AT("int32", "Number", sizeof(int32), sizeof(int32), alignof(int32)));

		if (FNameSize >= (int32)(sizeof(int32) * 3))
			T.Properties.push_back(DISASM_MEMBER_AT("int32", "DisplayIndex", sizeof(int32) * 2, sizeof(int32), alignof(int32)));
	}

	// TWeakObjectPtr: { int32 ObjectIndex; int32 ObjectSerialNumber; }
	{
		PredefinedStruct& T = AddPredef("TWeakObjectPtr", FWeakObjectPtrSize, alignof(int32));
		T.Properties = {
			DISASM_MEMBER_AT("int32", "ObjectIndex",        0,             sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32", "ObjectSerialNumber", sizeof(int32), sizeof(int32), alignof(int32)),
		};
	}

	// FScriptDelegate: { TWeakObjectPtr Object; FName FunctionName; } runtime FNameSize
	{
		PredefinedStruct& T = AddPredef("FScriptDelegate", PropertySizes::DelegateProperty, alignof(int32));
		T.Properties = {
			DISASM_MEMBER_AT("struct TWeakObjectPtr", "Object",       0,                  FWeakObjectPtrSize, alignof(int32)),
			DISASM_MEMBER_AT("struct FName",          "FunctionName", FWeakObjectPtrSize, FNameSize,          alignof(int32)),
		};
	}

	// FMulticastInlineDelegate: { TArray<FScriptDelegate> InvocationList; }
	{
		PredefinedStruct& T = AddPredef("FMulticastInlineDelegate", PropertySizes::MulticastInlineDelegateProperty, alignof(TArray<int>));
		T.Properties = {
			DISASM_MEMBER_AT("struct TArray", "InvocationList", 0, sizeof(TArray<int>), alignof(TArray<int>)),
		};
	}

	// TScriptInterface: { UObject* ObjectPointer; void* InterfacePointer; }
	{
		PredefinedStruct& T = AddPredef("TScriptInterface", PtrSize * 2, alignof(void*));
		T.Properties = {
			DISASM_MEMBER_AT("void*", "ObjectPointer",    0,       PtrSize, alignof(void*)),
			DISASM_MEMBER_AT("void*", "InterfacePointer", PtrSize, PtrSize, alignof(void*)),
		};
	}

	// FGuid: { uint32 A, B, C, D; }
	{
		PredefinedStruct& T = AddPredef("FGuid", static_cast<int32>(sizeof(uint32) * 4), alignof(uint32));
		T.Properties = {
			DISASM_MEMBER_AT("uint32", "A", sizeof(uint32) * 0, sizeof(uint32), alignof(uint32)),
			DISASM_MEMBER_AT("uint32", "B", sizeof(uint32) * 1, sizeof(uint32), alignof(uint32)),
			DISASM_MEMBER_AT("uint32", "C", sizeof(uint32) * 2, sizeof(uint32), alignof(uint32)),
			DISASM_MEMBER_AT("uint32", "D", sizeof(uint32) * 3, sizeof(uint32), alignof(uint32)),
		};
	}

	// TMap / TSet: no member breakdown (mirrors IDA's table); trailing pad carries the size.
	AddPredef("TMap", sizeof(TMap<int, int>), alignof(TMap<int, int>));
	AddPredef("TSet", sizeof(TSet<int>),      alignof(TSet<int>));

	// TFieldPath: { FField* ResolvedField; TWeakObjectPtr ResolvedOwner; TArray<FName> Path; }
	{
		PredefinedStruct& T = AddPredef("TFieldPath", PropertySizes::FieldPathProperty, alignof(void*));
		T.Properties = {
			DISASM_MEMBER_AT("struct FField*",        "ResolvedField", 0,                            PtrSize,             alignof(void*)),
			DISASM_MEMBER_AT("struct TWeakObjectPtr", "ResolvedOwner", PtrSize,                      FWeakObjectPtrSize,  alignof(int32)),
			DISASM_MEMBER_AT("struct TArray",         "Path",          PtrSize + FWeakObjectPtrSize, sizeof(TArray<int>), alignof(TArray<int>)),
		};
	}

	// FUObjectItem: { UObject* Object; ... padding to FUObjectItemSize } runtime offsets
	{
		PredefinedStruct& T = AddPredef("FUObjectItem", Off::InSDK::ObjArray::FUObjectItemSize, PtrSize);
		T.Properties = {
			DISASM_MEMBER_AT("void*", "Object", Off::InSDK::ObjArray::FUObjectItemInitialOffset, PtrSize, alignof(void*)),
		};
	}

	// TUObjectArray: chunked vs fixed layout
	if (Off::InSDK::ObjArray::ChunkSize > 0)
	{
		const auto& Layout = Off::FUObjectArray::ChunkedFixedLayout;
		const int32 ObjectArraySize = (std::max)({ Layout.ObjectsOffset + PtrSize, Layout.MaxElementsOffset + (int32)sizeof(int32), Layout.NumElementsOffset + (int32)sizeof(int32), Layout.MaxChunksOffset + (int32)sizeof(int32), Layout.NumChunksOffset + (int32)sizeof(int32) });

		PredefinedStruct& T = AddPredef("TUObjectArray", ObjectArraySize, PtrSize);
		T.Properties = {
			DISASM_MEMBER_AT("struct FUObjectItem**", "Objects",     Layout.ObjectsOffset,     PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32",                 "MaxElements", Layout.MaxElementsOffset, sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32",                 "NumElements", Layout.NumElementsOffset, sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32",                 "MaxChunks",   Layout.MaxChunksOffset,   sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32",                 "NumChunks",   Layout.NumChunksOffset,   sizeof(int32), alignof(int32)),
		};
	}
	else
	{
		const auto& Layout = Off::FUObjectArray::FixedLayout;
		const int32 ObjectArraySize = (std::max)({ Layout.ObjectsOffset + PtrSize, Layout.MaxObjectsOffset + (int32)sizeof(int32), Layout.NumObjectsOffset + (int32)sizeof(int32) });

		PredefinedStruct& T = AddPredef("TUObjectArray", ObjectArraySize, PtrSize);
		T.Properties = {
			DISASM_MEMBER_AT("struct FUObjectItem*", "Objects",     Layout.ObjectsOffset,    PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32",                "MaxObjects",  Layout.MaxObjectsOffset, sizeof(int32), alignof(int32)),
			DISASM_MEMBER_AT("int32",                "NumObjects",  Layout.NumObjectsOffset, sizeof(int32), alignof(int32)),
		};
	}

	// TNameEntryArray: only when not using FNamePool
	if (Off::InSDK::Name::AppendNameToString == 0x0 && !Settings::Internal::bUseNamePool)
	{
		const int32 ChunkTableSize = Off::NameArray::NumElements / PtrSize;
		const int32 ChunkTableSizeBytes = ChunkTableSize * PtrSize;
		const int32 NameArraySize = ChunkTableSizeBytes + PtrSize;

		PredefinedStruct& T = AddPredef("TNameEntryArray", NameArraySize, PtrSize);
		T.Properties = {
			DISASM_MEMBER_AT("void*", "Chunks",      0,                                          ChunkTableSizeBytes, alignof(void*)),
			DISASM_MEMBER_AT("int32", "NumElements", ChunkTableSizeBytes,                        sizeof(int32),       alignof(int32)),
			DISASM_MEMBER_AT("int32", "NumChunks",   ChunkTableSizeBytes + (int32)sizeof(int32), sizeof(int32),       alignof(int32)),
		};
	}

	// FStructBaseChain: void** (1 ptr) + int32 slot
	if (Off::UStruct::StructBaseChain != -1)
	{
		PredefinedStruct& T = AddPredef("FStructBaseChain", PtrSize * 2, alignof(void*));
		T.Properties = {
			DISASM_MEMBER_AT("void**", "StructBaseChainArray",          0,       PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("int32",  "NumStructBasesInChainMinusOne", PtrSize, sizeof(int32), alignof(int32)),
		};
	}

	// FField: { void* VTable; void* ClassPrivate; void* Owner; FField* Next; FName Name; int32 ObjFlags; }
	if (Settings::Internal::bUseFProperty)
	{
		PredefinedStruct& T = AddPredef("FField", PtrSize * 4 + FNameSize + (int32)sizeof(int32), PtrSize);
		T.Properties = {
			DISASM_MEMBER_AT("void*",          "VTable",       0,                       PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("void*",          "ClassPrivate", PtrSize,                 PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("void*",          "Owner",        PtrSize * 2,             PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("struct FField*", "Next",         PtrSize * 3,             PtrSize,       alignof(void*)),
			DISASM_MEMBER_AT("struct FName",   "Name",         PtrSize * 4,             FNameSize,     alignof(int32)),
			DISASM_MEMBER_AT("int32",          "ObjFlags",     PtrSize * 4 + FNameSize, sizeof(int32), alignof(int32)),
		};
	}

	// FText
	AddPredef("FText", Off::InSDK::Text::TextSize, alignof(void*));

	return Types;
}

#undef DISASM_MEMBER_AT

/* ------------------------------------------------------------------------------------------------
 * Package ordering / global walk
 * ------------------------------------------------------------------------------------------------ */

std::vector<PackageInfoHandle> DisassemblerMappingEmitter::CollectPackagesInDependencyOrder()
{
	std::vector<PackageInfoHandle> Packages;

	for (PackageInfoHandle Package : PackageManager::IterateOverPackageInfos())
	{
		if (!Package.IsEmpty())
			Packages.push_back(Package);
	}

	/*
	* A struct may embed (by value) types from other packages; the header is one file, so packages
	* must be written dependency-first or the C parser sees incomplete types. Package-level dependency
	* lists come from PackageManager (the same data CppGenerator's #include ordering uses).
	*/
	std::unordered_map<int32, std::unordered_set<int32>> Dependencies;
	std::unordered_set<int32> KnownPackages;
	std::unordered_set<int32> AllPackageIndices;

	for (const PackageInfoHandle& Package : Packages)
		KnownPackages.insert(Package.GetIndex());

	for (const PackageInfoHandle& Package : Packages)
	{
		const DependencyInfo& Info = Package.GetPackageDependencies();

		std::unordered_set<int32>& Deps = Dependencies[Package.GetIndex()];

		auto AddKeys = [&Deps, &KnownPackages, Own = Package.GetIndex()](const DependencyListType& List) -> void
		{
			for (const auto& [PackageIdx, Requirement] : List)
			{
				(void)Requirement;

				if (PackageIdx != Own && KnownPackages.contains(PackageIdx))
					Deps.insert(PackageIdx);
			}
		};

		AddKeys(Info.StructsDependencies);
		AddKeys(Info.ClassesDependencies);
		AddKeys(Info.ParametersDependencies);
	}

	/* Kahn-style sweeps; on a dependency cycle fall back to the original order for the rest. */
	std::vector<PackageInfoHandle> Ordered;
	Ordered.reserve(Packages.size());

	while (Ordered.size() < Packages.size())
	{
		bool bMadeProgress = false;

		for (const PackageInfoHandle& Package : Packages)
		{
			if (AllPackageIndices.contains(Package.GetIndex()))
				continue;

			const std::unordered_set<int32>& Deps = Dependencies[Package.GetIndex()];

			const bool bAllDepsEmitted = [&]() -> bool
			{
				for (int32 Dep : Deps)
				{
					if (!AllPackageIndices.contains(Dep))
						return false;
				}
				return true;
			}();

			if (bAllDepsEmitted)
			{
				Ordered.push_back(Package);
				AllPackageIndices.insert(Package.GetIndex());
				bMadeProgress = true;
			}
		}

		if (bMadeProgress)
			continue;

		/* Cycle: emit the first not-yet-ordered package anyway. */
		for (const PackageInfoHandle& Package : Packages)
		{
			if (!AllPackageIndices.contains(Package.GetIndex()))
			{
				Ordered.push_back(Package);
				AllPackageIndices.insert(Package.GetIndex());
				break;
			}
		}
	}

	return Ordered;
}

/* ------------------------------------------------------------------------------------------------
 * Loader script (load.rz / load.r2)
 * ------------------------------------------------------------------------------------------------ */

uint64 DisassemblerMappingEmitter::GetPreferredImageBase()
{
	/*
	* rizin has no usable base-address expression (unknown identifiers evaluate to 0), so absolute
	* addresses are baked at dump time from the PE's preferred ImageBase + RVA. Off::InSDK::* are
	* RVAs (Address - ModuleBase, see Platform::GetOffset).
	*/
	const uintptr_t RuntimeBase = Platform::GetModuleBase();
	const uint8_t*const Base = reinterpret_cast<const uint8_t*>(RuntimeBase);

	if (RuntimeBase == 0 || *reinterpret_cast<const uint16_t*>(Base) != 0x5A4D /* 'MZ' */)
		return RuntimeBase;

	const int32 Lfanew = *reinterpret_cast<const int32*>(Base + 0x3C);
	const uint8_t* NtHeaders = Base + Lfanew;

	if (Lfanew <= 0 || *reinterpret_cast<const uint32_t*>(NtHeaders) != 0x00004550 /* 'PE\0\0' */)
		return RuntimeBase;

	// OptionalHeader.Magic: 0x20B = PE32+ (ImageBase u64 @ +24), 0x10B = PE32 (ImageBase u32 @ +28)
	const uint16_t Magic = *reinterpret_cast<const uint16_t*>(NtHeaders + 24);

	if (Magic == 0x20B)
		return *reinterpret_cast<const uint64_t*>(NtHeaders + 24 + 24);

	return *reinterpret_cast<const uint32_t*>(NtHeaders + 24 + 28);
}

void DisassemblerMappingEmitter::WriteLoaderScript(const fs::path& OutFolder, const fs::path& HeaderFile, EDisassemblerDialect Dialect)
{
	const bool bIsRizin = (Dialect == EDisassemblerDialect::Rizin);
	const std::string ScriptName = bIsRizin ? "load.rz" : "load.r2";

	/* Paths must be the ones the dumper wrote. rizin needs quotes (space-safe), r2 takes the rest of the line. */
	const std::string HeaderPath = fs::absolute(HeaderFile).generic_string();

	std::stringstream Script;

	Script << "# Generated by vova-dumper\n";
	Script << "# " << Settings::Generator::GameVersion << "-" << Settings::Generator::GameName << "\n";
	Script << "e asm.bits=64\n";

	if (bIsRizin)
		Script << "to \"" << HeaderPath << "\"\n";
	else
		Script << "to " << HeaderPath << "\n";

	/* Named variables, mirroring IDAMappingGenerator::Generate()'s named vars (offsets + type strings). */
	struct FNamedVar
	{
		int64 Offset;
		const char* Type;
		const char* Name;
		bool bInclude;
	};

	const char* GNamesType = Settings::Internal::bUseNamePool ? "TNameEntryArray" : "FNamePool";

	const bool bIncludeAppendString = (Off::InSDK::Name::AppendNameToString != 0x0);
	const char* AppendStringName = Off::InSDK::Name::bIsUsingAppendStringOverToString ? "FName::AppendString" : "FName::ToString";
	const char* AppendStringType = Off::InSDK::Name::bIsUsingAppendStringOverToString
		? "void __fastcall (*)(const FName *This, FString *OutString);"
		: "FString* __fastcall (*)(const FName *This) const;";

	const FNamedVar Vars[] =
	{
		{ static_cast<int64>(Off::InSDK::ObjArray::GObjects),      "TUObjectArray",                                                             "GObjects",                    true                             },
		{ static_cast<int64>(Off::InSDK::NameArray::GNames),        GNamesType,                                                                  "GNames",                      true                             },
		{ static_cast<int64>(Off::InSDK::World::GWorld),            "UWorld*",                                                                   "GWorld",                      Off::InSDK::World::GWorld != 0x0 },
		{ static_cast<int64>(Off::InSDK::ProcessEvent::PEOffset),   "void __fastcall (*)(UObject *This, UFunction *Function, void *Params);",    "UObject::ProcessEvent",       Off::InSDK::ProcessEvent::PEOffset != 0x0 },
		{ static_cast<int64>(Off::InSDK::Name::AppendNameToString), AppendStringType,                                                            AppendStringName,              bIncludeAppendString             },
		{ static_cast<int64>(Off::InSDK::Name::GetNameEntryFromName), "void*",                                                                   "FName::GetNameEntryFromName", Off::InSDK::Name::GetNameEntryFromName != 0x0 },
	};

	const uint64 ImageBase = bIsRizin ? GetPreferredImageBase() : 0x0;

	for (const FNamedVar& Var : Vars)
	{
		if (!Var.bInclude)
			continue;

		const uint64 Rva = static_cast<uint64>(Var.Offset);

		if (bIsRizin)
		{
			/* rizin: absolute address (no working base expression), flag comment carries the type string. */
			Script << "f " << Var.Name << " 0x8 @ 0x" << std::uppercase << std::hex << (ImageBase + Rva) << std::nouppercase << std::dec << "\n";
			Script << "fC " << Var.Name << " " << Var.Type << "\n";
		}
		else
		{
			/* radare2: relative to $b so it survives rebasing; type string as a '#' comment. */
			Script << "# " << Var.Type << " " << Var.Name << "\n";
			Script << "f " << Var.Name << " = $b + 0x" << std::uppercase << std::hex << Rva << std::nouppercase << std::dec << "\n";
		}
	}

	/* Binary mode keeps LF line endings, which is what both tools were verified against. */
	std::ofstream ScriptFile(OutFolder / ScriptName, std::ios::binary);

	const std::string ScriptStr = Script.str();
	ScriptFile.write(ScriptStr.data(), ScriptStr.size());
}

/* ------------------------------------------------------------------------------------------------
 * Generate
 * ------------------------------------------------------------------------------------------------ */

void DisassemblerMappingEmitter::Generate(const fs::path& OutFolder, EDisassemblerDialect Dialect)
{
	std::string HeaderFileName = (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName + "_types.h");
	FileNameHelper::MakeValidFileName(HeaderFileName);

	const fs::path HeaderFilePath = OutFolder / HeaderFileName;

	std::stringstream Header;

	/*
	* No top-level comments in the emitted header: rizin 0.9.1 answers every comment spelling
	* (line, block, and even a bare hash line) with 'Unsupported type definition'. Each one is
	* non-fatal -- every type still loads -- but a file that prints errors on every load is a
	* bad artifact, so the header stays comment-free for rizin's sake. Inline comments INSIDE a
	* struct body are accepted by both tools (verified), which is why enum/bitfield annotations
	* survive on member lines. The load instructions live in load.rz / load.r2 instead, whose
	* '#' comments rizin does accept.
	*/

	const std::vector<PackageInfoHandle> Packages = CollectPackagesInDependencyOrder();

	/* Forward declarations first: members reference structs by pointer before their definitions. */
	EmitForwardDeclarations(Header, Packages);

	/* Enums (standalone plain-C tags; enum-backed members are laid out as integers + comment). */
	for (const PackageInfoHandle& Package : Packages)
	{
		if (!Package.HasEnums())
			continue;

		for (int32 EnumIdx : Package.GetEnums())
			EmitEnum(Header, EnumWrapper(ObjectArray::GetByIndex<UEEnum>(EnumIdx)));
	}

	Header << "\n";

	/* Predefined engine types (TArray, FName, ...), before anything embeds them by value. */
	{
		std::vector<PredefinedStruct> PredefinedTypes = BuildPredefinedTypes();

		for (const PredefinedStruct& Predef : PredefinedTypes)
			EmitStruct(Header, StructWrapper(&Predef), Dialect);
	}

	/* Reflected structs and classes, dependency-sorted within each package. */
	for (const PackageInfoHandle& Package : Packages)
	{
		DependencyManager::OnVisitCallbackType Visit = [&](int32 Index) -> void
		{
			EmitStruct(Header, StructWrapper(ObjectArray::GetByIndex<UEStruct>(Index)), Dialect);
		};

		if (Package.HasStructs())
			Package.GetSortedStructs().VisitAllNodesWithCallback(Visit);

		if (Package.HasClasses())
			Package.GetSortedClasses().VisitAllNodesWithCallback(Visit);
	}

	/* Write header (binary => LF line endings, verified against both parsers). */
	{
		std::ofstream HeaderFile(HeaderFilePath, std::ios::binary);
		const std::string HeaderStr = Header.str();
		HeaderFile.write(HeaderStr.data(), HeaderStr.size());
	}

	WriteLoaderScript(OutFolder, HeaderFilePath, Dialect);
}

/* ------------------------------------------------------------------------------------------------
 * Generator entry points
 * ------------------------------------------------------------------------------------------------ */

void RizinMappingGenerator::Generate()
{
	DisassemblerMappingEmitter::Generate(MainFolder, EDisassemblerDialect::Rizin);
}

void RizinMappingGenerator::InitPredefinedMembers()
{
	InitCorePredefinedMembers(PredefinedMembers);

	for (auto& [Index, Predefs] : PredefinedMembers)
		std::sort(Predefs.Members.begin(), Predefs.Members.end(), ComparePredefinedMembers);
}

void Radare2MappingGenerator::Generate()
{
	DisassemblerMappingEmitter::Generate(MainFolder, EDisassemblerDialect::Radare2);
}

void Radare2MappingGenerator::InitPredefinedMembers()
{
	InitCorePredefinedMembers(PredefinedMembers);

	for (auto& [Index, Predefs] : PredefinedMembers)
		std::sort(Predefs.Members.begin(), Predefs.Members.end(), ComparePredefinedMembers);
}
