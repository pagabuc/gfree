#include <utility>
#include <iomanip>
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Target/TargetRegisterInfo.h"
#include "llvm/Support/CommandLine.h"

#ifndef GFREEUTILS_H_
#define GFREEUTILS_H_

#define DEBUGLEVEL -1
#define GFreeDEBUG(level, ...) \
  do { if (level <= DEBUGLEVEL) errs() << std::string(!level? 0: (level)*4,' ') << __VA_ARGS__; } while (0)

using namespace llvm;

/* static cl::opt<bool>  */
/* DisableGFree("disable-gfree", cl::Hidden, */
/* 	       cl::desc("Disable GFree protections")); */

/* Global Variables */
extern cl::opt<bool> DisableGFree;


std::pair<int64_t, int64_t> splitInt(int64_t Imm, int Size);

bool isIndirectCall(MachineInstr *MI);
bool isMove(MachineInstr *MI);
bool isTest(MachineInstr *MI);
bool isCompare(MachineInstr *MI);
bool isArithmUsesEFLAGS(MachineInstr *MI);

const TargetRegisterClass *getRegClassFromSize(int size);
int getORrrOpcode(unsigned int size);
int getMOVriOpcode(unsigned int size);
int getADDrrOpcode(unsigned int size);
int getSUBrrOpcode(unsigned int size);
int getORriOpcode(unsigned int size);

bool containsRet(std::vector<unsigned char> MIbytes);
bool contains(std::vector<llvm::MachineInstr*> v, MachineInstr* mbb);

void emitNop(MachineInstr *MI, int count=1);
void emitNopAfter(MachineInstr *MI, int count=1);
MachineInstrBuilder pushReg(MachineInstr *MI, unsigned int Reg, unsigned int flags=0);
MachineInstrBuilder popReg(MachineInstr *MI, unsigned int Reg, unsigned int flags=0);
bool needToSaveEFLAGS(MachineInstr *MI);
void pushEFLAGS(MachineInstr *MI);
void popEFLAGS(MachineInstr *MI);
void pushEFLAGSinline(MachineInstr *MI, unsigned int saveRegEFLAGS);
void popEFLAGSinline(MachineInstr *MI, unsigned int saveRegEFLAGS);

void dumpSuccessors(MachineBasicBlock *fromMBB);

#endif
