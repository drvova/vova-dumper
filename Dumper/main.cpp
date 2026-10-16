#include <Windows.h>
#include <iostream>
#include <chrono>
#include <fstream>

#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"
#include "Generators/DisassemblerMappingGenerator.h"

#include "Generators/Generator.h"

enum class EFortToastType : uint8
{
    Default                                  = 0,
    Subdued                                  = 1,
    Impactful                                = 2,
    Lock                                     = 3,
    EFortToastType_MAX                       = 4,
};

/* Mirrors the dumper's console output into C:/vova-dumper/dumper-tee.log so a
   crashed run still leaves the resolved offsets and the last processed object
   behind. Lives inside MainThread so it wraps the already-redirected stderr. */
class TeeBuf : public std::streambuf
{
	std::streambuf* Console;
	std::streambuf* File;
public:
	TeeBuf(std::streambuf* ConsoleBuf, std::streambuf* FileBuf)
		: Console(ConsoleBuf), File(FileBuf)
	{
		std::cerr.rdbuf(this);
	}

	int overflow(int C) override
	{
		if (C == EOF)
			return !EOF;

		if (Console && Console->sputc(static_cast<char>(C)) == EOF)
			return EOF;

		if (!File || File->sputc(static_cast<char>(C)) == EOF)
			return EOF;

		if (C == '\n') /* keep the log tail alive across hard crashes */
			File->pubsync();

		return C;
	}

	int sync() override
	{
		if (Console && Console->pubsync() != 0)
			return -1;

		return File ? File->pubsync() : 0;
	}
};

DWORD MainThread(HMODULE Module)
{
	AllocConsole();
	FILE* Dummy;
	freopen_s(&Dummy, "CONIN$", "r", stdin);
	freopen_s(&Dummy, "CONOUT$", "w", stderr);
	freopen_s(&Dummy, "CONOUT$", "w", stdout);
	std::cerr.clear(); // clear internal error flags on cerr after redirect
	std::cerr << std::boolalpha << std::hex;

	std::ofstream TeeFile("C:/vova-dumper/dumper-tee.log", std::ios::out | std::ios::trunc);
	TeeBuf Tee(std::cerr.rdbuf(), TeeFile.is_open() ? TeeFile.rdbuf() : nullptr);

	std::cerr << "vova-dumper build: " << __DATE__ << " " << __TIME__ << "\n";
	std::cerr << "Initializing [vova-dumper]\n";

	Settings::Config::Load();
	Settings::Config::DelayDumperStart();

	std::cerr << "Started Generation [vova-dumper]!\n";
	auto DumpStartTime = std::chrono::high_resolution_clock::now();

	const bool bInitSuccess = Generator::InitEngineCore() && Generator::InitInternal();

	if (bInitSuccess)
	{

		if (Settings::Generator::GameName.empty() && Settings::Generator::GameVersion.empty())
		{
			// Only Possible In Main()
			FString Name;
			FString Version;
			UEClass Kismet = ObjectArray::FindClassFast("KismetSystemLibrary");

			if (Kismet)
			{
				UEFunction GetGameName = Kismet.GetFunction("KismetSystemLibrary", "GetGameName");
				UEFunction GetEngineVersion = Kismet.GetFunction("KismetSystemLibrary", "GetEngineVersion");

				if (GetGameName && GetEngineVersion)
				{
					Kismet.ProcessEvent(GetGameName, &Name);
					Kismet.ProcessEvent(GetEngineVersion, &Version);

					Settings::Generator::GameName = Name.ToString();
					Settings::Generator::GameVersion = Version.ToString();
				}
			}
		}

		std::cerr << "GameName: " << Settings::Generator::GameName << "\n";
		std::cerr << "GameVersion: " << Settings::Generator::GameVersion << "\n\n";

		std::cerr << "FolderName: " << (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName) << "\n\n";

		Generator::Generate<CppGenerator>();
		Generator::Generate<MappingGenerator>();
		Generator::Generate<IDAMappingGenerator>();
		Generator::Generate<DumpspaceGenerator>();
		Generator::Generate<RizinMappingGenerator>();
		Generator::Generate<Radare2MappingGenerator>();

		auto DumpFinishTime = std::chrono::high_resolution_clock::now();

		std::chrono::duration<double, std::milli> DumpTime = DumpFinishTime - DumpStartTime;

		std::cerr << "\n\nGenerating SDK took (" << DumpTime.count() << "ms)\n\n\n";
	}
	else
	{
		std::cerr << "\nEngine init failed; skipping SDK generation. Press F6 to unload.\n\n";
	}

	if (Settings::Debug::bExecuteSDKTestScript)
	{
		/* Executes a python script to test if the SDK compiles correctly. */
		CppGenerator::ExecuteSDKCompilationTestScript();
	}

	std::cerr << "\n\nPress F6 to unload\n\n\n";

	while (true)
	{
		if (GetAsyncKeyState(VK_F6) & 1)
		{
			fclose(stderr);
			if (Dummy) 
			{
				fclose(Dummy);
			}
			FreeConsole();

			FreeLibraryAndExitThread(Module, 0);
		}

		Sleep(100);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}
