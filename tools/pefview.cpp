#include <chrono>
#include <fstream>
#include <print>

#include "../src/PEF.hpp"

int main(int argc, char **argv)
{
	if (argc != 2) return 1;

	std::ifstream input(argv[1], std::ios::binary);
	PEFFile f(input);
	input.close();

	auto h = f.GetHeader();
	std::println("Magic:\t\t{:08X}", h.magic);
	std::println("Type:\t\t{:08X}", h.type);
	std::println("Arch:\t\t{:08X}", h.arch);
	std::println("Version:\t\t{}", h.fmtver);
	std::println("Date:\t\t{:X}", h.date);
	std::println("Old Def:\t\t{}", h.olddefver);
	std::println("Old Impl:\t\t{}", h.oldimplver);
	std::println("Current:\t\t{}", h.curver);
	std::println("# Sections:\t\t{}", h.nsections);
	std::println("# Inst. Sects:\t\t{}", h.ninstsections);
	std::println();
	std::println();

	for (auto s : sects)
	{
		std::println("Name offset:\t\t{}", s.nameoffs);
		std::println("Default addr:\t\t{:08X}", s.defaultaddr);
		std::println("Total size:\t\t{:X}", s.totalsize);
		std::println("Unpacked size:\t\t{:X}", s.unpackedsize);
		std::println("Packed size:\t\t{:X}", s.packedsize);
		std::println("Offset:\t\t\t{:X}", s.offs);
		std::println("Kind:\t\t\t{}", s.kind);
		std::println("Share kind:\t\t{}", s.sharekind);
		std::println("Alignment:\t\t{}", s.align);
		std::println();
	}

	return 0;
}