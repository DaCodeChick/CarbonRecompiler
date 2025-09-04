#pragma once

#include <cstdint>
#include <istream>
#include <llvm/MC/MCInst.h>
#include <string>
#include <vector>

struct PEFHeader
{
	uint32_t magic; // 'Joy!'
	uint32_t type; // 'peff'
	uint32_t arch; // 'pwpc'
	uint32_t fmtver; // 1 for Mac OS 9
	uint32_t date;
	uint32_t olddefver;
	uint32_t oldimplver;
	uint32_t curver;
	uint16_t nsections;
	uint16_t ninstsections;
	uint32_t reserved;
};


struct PEFSectionHeader
{
	int32_t nameoffs;
	uint32_t defaultaddr;
	uint32_t totalsize;
	uint32_t unpackedsize;
	uint32_t packedsize;
	uint32_t offs;
	uint8_t kind;
	uint8_t sharekind;
	uint8_t align;
	uint8_t reserved;
};


struct PEFLoaderHeader
{
	int32_t mainsect; // -1 if none
	uint32_t mainoffs;
	int32_t initsect; // -1 if none
	uint32_t initoffs;
	int32_t termsect; // -1 if none
	uint32_t termoffs;
	uint32_t nimplibs;
	uint32_t nimpsyms;
	uint32_t nrelocsects;
	uint32_t relocinstroffs; // relative
	uint32_t loaderstroffs; // relative
	uint32_t exphashoffs; // relative
	uint32_t exphashtblpow;
	uint32_t nexpsyms;
};


struct PEFImportHeader
{
	uint32_t nameoffs;
	uint32_t oldimpver;
	uint32_t curver;
	uint32_t nimpsyms;
	uint32_t impsym1idx;
	uint8_t options;
	uint8_t reserveda;
	uint16_t reservedb;
};


struct PEFRelocationHeader
{
	uint16_t idx;
	uint16_t reserved;
	uint32_t nrelocs;
	uint32_t reloc1offs;
};


struct PEFExportSymbol
{
	uint32_t classandname;
	uint32_t value;
	int16_t sectidx;
};


class PEFFile
{
public:
	PEFFile(std::istream &);
	const PEFSectionHeader * FindSectionByKind(uint8_t) const;

	constexpr PEFHeader & GetHeader() const
	{
		return _header;
	}
protected:
	static void ByteswapSectionHeader(PEFSectionHeader &);
private:
	PEFHeader _header;
	PEFLoaderHeader _loaderHeader;
	std::vector<PEFSectionHeader> _sectionHeaders;
	std::vector<MCInst> _insts;
	std::vector<std::string> _strs;
};
