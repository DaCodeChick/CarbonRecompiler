#pragma once

#include <llvm/IR/Value.h>
#include <map>
#include <string>


class PPCConverter
{
private:
	std::map<std::string, llvm::Value> _regs;
};
