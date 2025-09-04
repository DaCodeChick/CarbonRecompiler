#include <capstone/capstone.h>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <print>
#include <vector>

#include "../src/PEF.hpp"


int main(int argc, char **argv)
{
	if (argc != 2) return -1;

	std::ifstream input(argv[1], std::ios::binary);
	PEFFile pef(input);
	std::ofstream output(std::format("{}.S", argv[1]));
	auto sect = pef.FindSectionByKind(0);

	if (!sect) return -3;

	std::vector<uint8_t> bin(sect->totalsize);

	input.seekg(sect->offs);
	input.read(reinterpret_cast<char *>(&bin[0]), sect->totalsize);
	input.close();

	std::println("Total bytes read: {:X}", bin.size());

	csh h;

	if (cs_open(CS_ARCH_PPC, static_cast<cs_mode>(CS_MODE_32 | CS_MODE_BIG_ENDIAN), &h) != CS_ERR_OK)
		return -2;
	
	cs_insn *insn = cs_malloc(h);
	size_t mem_offs = 0x10000000;
	size_t bin_offs = 0;

	while (bin_offs < sect->totalsize)
	{
		const uint8_t *p = bin.data() + bin_offs;
		size_t rem = sect->totalsize - bin_offs;

		// if a no-op is encountered, first byte is 0x60, the rest null
		// so this should suffice
		while (rem > 0 && (!(*p) ||
			*reinterpret_cast<const uint32_t *>(p) == 0x60000000))
		{
			bin_offs++;
			mem_offs++;
			p++;
			rem--;
		}

		if (rem > 0 && cs_disasm_iter(h, &p, &rem, &mem_offs, insn))
		{
			output << std::format("{:08X}:\t{}\t\t{}\n", insn->address, insn->mnemonic, insn->op_str);
			bin_offs += insn->size;
		}
		else
		{
			bin_offs++;
			mem_offs++;
		}
	}

	output.close();
	cs_free(insn, 1);
	cs_close(&h);

	return 0;
}
