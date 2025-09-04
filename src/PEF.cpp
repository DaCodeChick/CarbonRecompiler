#include <boost/endian/conversion.hpp>
#include <cstring>

#include "PEF.hpp"


PEFFile::PEFFile(std::istream &s)
{
	s.read(reinterpret_cast<char *>(&_header), sizeof(PEFHeader));

	boost::endian::big_to_native_inplace(_header.magic);
	boost::endian::big_to_native_inplace(_header.type);
	boost::endian::big_to_native_inplace(_header.arch);
	boost::endian::big_to_native_inplace(_header.fmtver);
	boost::endian::big_to_native_inplace(_header.date);
	boost::endian::big_to_native_inplace(_header.olddefver);
	boost::endian::big_to_native_inplace(_header.oldimplver);
	boost::endian::big_to_native_inplace(_header.curver);
	boost::endian::big_to_native_inplace(_header.ninstsections);

	_sectionHeaders.resize(_header.nsections);

	for (auto i = 0; i < _header.nsections; i++)
	{
		s.read(reinterpret_cast<char *>(&_sectionHeaders[i]), sizeof(PEFSectionHeader));
		ByteswapSectionHeader(_sectionHeaders[i]);
	}

	auto codeSect = FindSectionByKind(0);
	if (!codeSect) return;

	std::vector<uint8_t> bin(codeSect->totalsize);
	s.seekg(codeSect->offs);
	s.read(reinterpret_cast<char *>(&bin[0]), codeSect->totalsize);

	csh h;
	if (cs_open(CS_ARCH_PPC, static_cast<cs_mode>(CS_MODE_32 | CS_MODE_BIG_ENDIAN), &h) != CS_ERR_OK)
		return;
	
	cs_insn *insn = cs_malloc(h);
	size_t mem_offs = 0x10000000;
	size_t bin_offs = 0;

	while (bin_offs < codeSect->totalsize)
	{
		const uint8_t *p = bin.data() + bin_offs;
		size_t rem = codeSect->totalsize - bin_offs;

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
			cs_insn copy;
			memmove(&copy, insn, sizeof(cs_insn));
			_insns.push_back(copy);
			bin_offs += insn->size;
		}
		else
		{
			bin_offs++;
			mem_offs++;
		}
	}

	cs_free(insn, 1);
	cs_close(&h);
}


void PEFFile::ByteswapSectionHeader(PEFSectionHeader &h)
{
	boost::endian::big_to_native_inplace(h.nameoffs);
	boost::endian::big_to_native_inplace(h.defaultaddr);
	boost::endian::big_to_native_inplace(h.totalsize);
	boost::endian::big_to_native_inplace(h.unpackedsize);
	boost::endian::big_to_native_inplace(h.packedsize);
	boost::endian::big_to_native_inplace(h.offs);
}


const PEFSectionHeader * PEFFile::FindSectionByKind(uint8_t kind) const
{
	for (auto i = 0; i < _sectionHeaders.size(); i++)
		if (_sectionHeaders[i].kind == kind)
			return &_sectionHeaders[i];
	return nullptr;
}
