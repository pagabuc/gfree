#include "X86.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Format.h"
#include "llvm/MC/MCContext.h"
#include "X86GFreeUtils.h"
#include "llvm/ADT/Statistic.h"
#include <stdlib.h> 
#include <time.h>   
#include "llvm/Support/Format.h"
using namespace llvm;

//  Then, on the command line, you can specify '-debug-only=foo'
#define DEBUG_TYPE "gfreeimmediaterecon"
STATISTIC(Jcp , "Number of cookies for call*/jmp* inserted");

namespace {
  class GFreeJCPPass : public MachineFunctionPass {
  public:
    GFreeJCPPass() : MachineFunctionPass(ID) {}
    bool runOnMachineFunction(MachineFunction &MF) override;
    const char *getPassName() const override {return "Jump Control Protection Pass";}
    static char ID;
  };
  char GFreeJCPPass::ID = 0;
}

int64_t GFreeCookieCostant;

FunctionPass *llvm::createGFreeJCPPass() {
  return new GFreeJCPPass();
}

// Put the cookie on the stack at the beginning of a function.
void insertCookieIndirectJump(MachineInstr* MI, int index){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 

  // unsigned int VirtReg = MF->getRegInfo().createVirtualRegister(&X86::GR64RegClass);
  // unsigned int UselessReg = MF->getRegInfo().createVirtualRegister(&X86::GR64RegClass);

  // Here we are in the prologue of a function, R11 can be clobbered.
  unsigned int VirtReg = X86::R11;
  unsigned int UselessReg = X86::R11;
  MBB->addLiveIn(X86::R11);
  MBB->sortUniqueLiveIns();

  // mov $imm, %VirtReg
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::MOV64ri)).addReg(VirtReg, RegState::Define);
  MIB.addImm(GFreeCookieCostant);
  GFreeDEBUG(2, "> " << *MIB);

  // xor %fs:0x28, %VirtReg
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::XOR64rm)).addReg(UselessReg, RegState::Define)
    .addReg(VirtReg).addReg(0).addImm(1).addReg(0).addImm(0x28).addReg(X86::FS);
  GFreeDEBUG(2, "> " << *MIB);

  // mov VirtReg, (StackIndex)
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::MOV64mr));
  addFrameReference(MIB, index);
  MIB.addReg(UselessReg);
  GFreeDEBUG(2, "> " << *MIB);

  // This is for security. wipe virtreg since it contains %fs:0x28.
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::XOR64rr))
    .addReg(UselessReg, RegState::Define)
    .addReg(VirtReg, RegState::Kill)
    .addReg(VirtReg);
  GFreeDEBUG(2,"> " << *MIB);

  // MF->verify();
}

void insertCheckCookieIndirectJump(MachineInstr* MI, int index){
  
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 

  // unsigned int VirtReg = MF->getRegInfo().createVirtualRegister(&X86::GR64RegClass);
  // unsigned int TmpReg = MF->getRegInfo().createVirtualRegister(&X86::GR64RegClass);

  unsigned int VirtReg = X86::R11; 
  unsigned int TmpReg = X86::R11; 
  MBB->addLiveIn(X86::R11);
  MBB->sortUniqueLiveIns();

  // Here we are in the middle of a function, so r11 can't be clobbered.
  pushReg(MI,X86::R11, RegState::Undef);

  // mov $imm, %VirtReg
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::MOV64ri)).addReg(VirtReg, RegState::Define);
  MIB.addImm(GFreeCookieCostant);
  GFreeDEBUG(2, "> " << *MIB);

  // xor (stack), %VirtReg
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::XOR64rm)).addReg(TmpReg, RegState::Define).addReg(VirtReg, RegState::Kill);
  addFrameReference(MIB, index);
  GFreeDEBUG(2, "> " << *MIB);

  // cmp VirtReg, fs:0x28
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::CMP64rm)).addReg(TmpReg)
    .addReg(0).addImm(1).addReg(0).addImm(0x28).addReg(X86::FS);
  GFreeDEBUG(2, "> " << *MIB);

  popReg(MI,X86::R11);

  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::NOOP));
  // GFreeDEBUG(2, "> " << *MIB);

}

int64_t generateSafeRandom(){
  std::pair<int64_t, int64_t> tmp_pair;
  int64_t rnd;
  do{
    rnd = rand();
    rnd = (rnd << 32) | rand();
    tmp_pair = splitInt(rnd,64);
  }while((tmp_pair.first != 0)); // If true it means splitInt found an evil bytes.

  // errs() << format("rnd=0x%016llx\n",rnd);

  return rnd;
}

// Main.
bool GFreeJCPPass::runOnMachineFunction(MachineFunction &MF) {
  // Generate the random costant for this function
  srand( time(0) + MF.getFunctionNumber() );
  GFreeCookieCostant = generateSafeRandom();
  MachineFunction::iterator MBB, MBBE;
  MachineBasicBlock::iterator MBBI, MBBIE;
  MachineInstr *MI;

  std::vector<llvm::MachineInstr*> alreadyCheckedInstr;
  MachineFrameInfo *MFI = MF.getFrameInfo();
  int index = -1;
  bool created = false;

  for (MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){

    if(MBB->empty())
      continue;

    for (MBBI = MBB->begin(), MBBIE = MBB->end(); MBBI != MBBIE; ++MBBI) {

      MI = MBBI;

      if( ( MI->isIndirectBranch() || isIndirectCall(MI) ) &&
	  !contains(alreadyCheckedInstr, MI) ){ 

	// Let's check the cookie...	
	GFreeDEBUG(0, "[!] Adding Check Cookie in " << MF.getName() << 
		   " MBB#" << MBB->getNumber() << " : " << *MI);      	

	if(!created){ 	// Create once and only once a new Stack Object.
	  index = MFI->CreateStackObject(8, 8, false);
	  created = true;
	}

	insertCheckCookieIndirectJump(MI, index);
	++Jcp; // Update stats.

	// Restart from the right point.
	alreadyCheckedInstr.push_back(MI);

      }
    }
  }

  // Skip empty MBBs.
  MBB = MF.begin();
  while(MBB->empty()){
    MBB = std::next(MBB);
  }

  if(MBB == MF.end()) return true;

  // In this function there is at least one indirect call.
  if( created ){
    GFreeDEBUG(0, "[!] Adding Cookie @ " << MF.getName() << "\n");      
    MBBI = MBB->begin();
    insertCookieIndirectJump(MBBI, index);
  }

  // MF.verify();
  return true;
}
