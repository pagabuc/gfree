//===-- X86GFree.cpp - Make your binary rop-free -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the pass ....
//
//===----------------------------------------------------------------------===//



#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86TargetMachine.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Support/raw_ostream.h"
#include "X86GFreeUtils.h"

using namespace llvm;

//  Then, on the command line, you can specify '-debug-only=foo'
#define DEBUG_TYPE "gfree"

STATISTIC(Rap , "Number of return address protection inserted");
namespace {

  class GFreeMachinePass : public MachineFunctionPass {
  public:
    GFreeMachinePass() : MachineFunctionPass(ID) {}
    bool runOnMachineFunction(MachineFunction &MF) override;
    const char *getPassName() const override { return "GFree Main Module"; }
    static char ID;
  };

  char GFreeMachinePass::ID = 0;
}

FunctionPass *llvm::createGFreeMachinePass() {
  return new GFreeMachinePass();
}

// 64bit => NO: rdx, rbx, r10, r11
// 32bit => NO: edx, ebx
bool handleBSWAP(MachineInstr *MI){
  assert(MI->getOperand(0).isReg() && "handleBSWAP can't handle this instr!");

  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  unsigned int bswapReg = MI->getOperand(0).getReg();
  std::set<unsigned int> unsafeRegSet = {X86::RDX, X86::RBX, X86::R10,
					 X86::R11, X86::EDX, X86::EBX};

  // If the register is not unsafe, return.
  if( unsafeRegSet.find(bswapReg) == unsafeRegSet.end() ){
    return false;
  }
  bool is32 = (MI->getOpcode() == X86::BSWAP32r);
  unsigned int safeReg = is32 ? X86::ECX : X86::RCX;
  unsigned int safeReg64 = X86::RCX;
  unsigned int OpcodeMOV = is32 ? X86::MOV32rr : X86::MOV64rr;
  unsigned int OpcodeBSWAP = is32 ? X86::BSWAP32r : X86::BSWAP64r;
  GFreeDEBUG(1,"[!] Found evil:" << *MI);
  // Save safe register
  pushReg(MI, safeReg64);
  
  // Load unsafe reg into the safe 
  MIB = BuildMI(*MBB, MI, DL, TII.get(OpcodeMOV)).addReg(safeReg).addReg(bswapReg);

  // bswap safeReg
  MIB = BuildMI(*MBB, MI, DL, TII.get(OpcodeBSWAP))
    .addReg(safeReg, RegState::Define)
    .addReg(safeReg, RegState::Kill);

  // Load safe into unsafe
  MIB = BuildMI(*MBB, MI, DL, TII.get(OpcodeMOV)).addReg(bswapReg).addReg(safeReg);

  // Restore safe register
  popReg(MI, safeReg64);
  return true;
}

bool handleMOVNTI(MachineInstr *MI){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB;

  bool is32 = (MI->getOpcode() == X86::MOVNTImr);
  unsigned int OpcodeMOV = is32 ? X86::MOV32mr : X86::MOV64mr;
  MIB = BuildMI(*MBB, MI, DL, TII.get(OpcodeMOV));
  // Copy all the operand from the old MOVNTI to the new MOV.
  for (unsigned I = 0, E = MI->getNumOperands(); I < E; ++I){
    MachineOperand *MO = new MachineOperand(MI->getOperand(I));
    MIB.addOperand(*MO);
  }
  GFreeDEBUG(2,"> " << *MIB);
  return true; 
}

void instructionTransformation(MachineFunction &MF){
  MachineInstr *MI;
  std::vector<MachineInstr*> toDelete; // This hold all the instructions that will be deleted.

  for (MachineFunction::iterator MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
    for (MachineBasicBlock::iterator MBBI = MBB->begin(), MBBIE = MBB->end(); MBBI != MBBIE; MBBI++) {
      MI = MBBI;
      unsigned Opc = MI->getOpcode();
      bool del = false;

      if( (Opc == X86::BSWAP64r) || (Opc == X86::BSWAP32r)){
	del = handleBSWAP(MI);	
      }

      if( (Opc == X86::MOVNTImr) || (Opc == X86::MOVNTI_64mr)){
	del = handleMOVNTI(MI);	
      }

      if (del){
	toDelete.push_back(MI);
      } 
    }
  }
  // Deleting instructions.
  for (std::vector<MachineInstr*>::iterator  I = toDelete.begin(); I != toDelete.end(); ++I){
    (*I)->eraseFromParent();
  }
}

MachineFunction* branchTargetFunction(MachineInstr *MI){
  // errs() << "[-] branchTargetFunction: " << *MI;
  assert("[-] jumpTarget called with a MI that's not a branch!" && MI->isBranch());
  return MI->getOperand(0).getMBB()->getParent();
}


void insertPrologueOrEpilogue(MachineInstr *MI, unsigned int retAddrRegister, 
			      unsigned int retAddrOffset, bool Prologue){

  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 

  // Create a new machine basic block to host the prologue. 
  if(Prologue){

    MachineBasicBlock *newMBB = MF->CreateMachineBasicBlock();
    MF->insert(MBB->getIterator(), newMBB);
    newMBB->addSuccessor(MBB);

    // Update for the next builds.
    MBB = newMBB;
    MI = MBB->begin();
    DL = MI->getDebugLoc();
  }

  MachineOperand r11_def = MachineOperand::CreateReg(X86::R11, true);
  MachineOperand r11_use = MachineOperand::CreateReg(X86::R11, false);

  // Emit the nopsled if we are emitting the epilogue.
  if(!Prologue){
    emitNop(MI, 9);
  }

  // mov    %fs:0x28,%r11
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::MOV64rm)).addOperand(r11_def)
    .addReg(0).addImm(1).addReg(0).addImm(0x28).addReg(X86::FS);
  GFreeDEBUG(2, "> " << *MIB); 	    

  // xor %r11, (%rsp)
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::XOR64mr));
  addRegOffset(MIB, retAddrRegister, false, retAddrOffset);
  MIB.addOperand(r11_use);
  GFreeDEBUG(2, "> " << *MIB); 	    

  MBB->addLiveIn(X86::R11);
  MBB->sortUniqueLiveIns();
}

void returnAddressProtection(MachineFunction &MF){
  GFreeDEBUG(2, "[+---- Return Address Protection @ ----+]\n");

  MachineFunction::iterator MBB = MF.begin();
  MachineFunction::iterator MBBE = MF.end();

  // Skips empty basic blocks.
  while(MBB->empty()){
    GFreeDEBUG(3, "[-] Oh no, this MBB is empty, check the next one. \n");
    MBB++;
  }
  if(MBB == MBBE){ // This shouldn't happen.
    return;
  }

  MachineBasicBlock::iterator MBBI;
  MachineBasicBlock::iterator MBBIE;

  MachineInstrBuilder MIB;
  MachineInstr *MI;  
  int retAddrOffset;
  int retAddrRegister;

  retAddrOffset = 0;
  retAddrRegister = X86::RSP;
  
  // Epilogue.
  bool inserted = false;

  for (MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
    if(MBB->empty()) continue;
    MI = std::prev(MBB->end());
    if(MI->isIndirectBranch()){
      continue; 
    }
    if ( ( MI->isReturn() ) ||
	 ( MI->isBranch() && branchTargetFunction(MI)->getFunctionNumber() != MF.getFunctionNumber() )){
      ++Rap; // update stats/
      insertPrologueOrEpilogue(MI, retAddrRegister, retAddrOffset, false);	  
      inserted = true;
    }
    if ( (std::next(MBB) == MBBE) && MI->isCall()){ // If the last inst of the last basic block is a call,
      inserted = true;                              // just put the epilogue.
    }
  }  
  if(inserted){
    GFreeDEBUG(0, "[!] Adding Prologue/Epilogue @ " << MF.getName() << "\n");
    MBB = MF.begin();
    while(MBB->empty()){
      GFreeDEBUG(3, "[-] Oh no, this MBB is empty, check the next one. \n");
      MBB++;
    }
    MI = MBB->begin();
    insertPrologueOrEpilogue(MI, retAddrRegister, retAddrOffset, true);
  }
  return; 
}


// This function checks if MI points to the bottom of the check cookie routine.
// It does perform some check and return:
// -1 if in MBB there will never be the routine we are looking for. The caller should proceed with another MBB.
//  0 if we found the routine
//  1 if we didn't found the routine, but the caller must keep looking for it in this MBB.
int matchCheckCookieRoutine(MachineInstr *MI){
  MachineBasicBlock *ParentMBB = MI->getParent();
  MachineBasicBlock::iterator ParentMIBegin = ParentMBB->begin();
  MachineBasicBlock::iterator tmpMI = MI;

  if(ParentMBB->size() < 5)
    return -1;

  if( (ParentMIBegin == tmpMI) ||
      (std::next(ParentMIBegin) == tmpMI))
    return -1;

  if ((std::prev(tmpMI,4)->getOpcode() == X86::PUSH64r) &&
      (std::prev(tmpMI,3)->getOpcode() == X86::MOV64ri) &&
      (std::prev(tmpMI,2)->getOpcode() == X86::XOR64rm) &&
      (std::prev(tmpMI,1)->getOpcode() == X86::CMP64rm ) &&
      (tmpMI->getOpcode() == X86::POP64r)             )
    return 0;

  return 1;
}

// This function finalize the cookie for jmp*/call*, and also adds a
// nop sled before the check..  Finalize means, for every jmp*/call*
// go backwards and find the block of instructions inserted from
// X86GFreeJCP.cpp that check the cookie. Bring them down, close to
// the jmp*/call*.
// Also, splice the MBB, put a jump and an hlt between the check and the
// jmp*/call* so the layout will be:

// check_cookie;
// je; -----------|
// hlt;           |
// jmp*/call*; <--|
// 

// This is a sample of the code for checking the cookie: 
// > %vreg25<def> = MOV64rm <fi#0>, 1, %noreg, 0, %noreg; mem:LD8[FixedStack0] GR64:%vreg25
// > %vreg26<def,tied1> = XOR64ri32 %vreg25<tied0>, 179027149, %EFLAGS<imp-def>; GR64:%vreg26,%vreg25
// > CMP64rm %vreg26, %noreg, 1, %noreg, 40, %FS, %EFLAGS<imp-def>; GR64:%vreg26

void cookieProtectionFinalization(MachineFunction &MF){
  GFreeDEBUG(2, "\n[+---- Jump Control Protection Finalization  ----+]\n");
  const X86Subtarget &STI = MF.getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  MachineFunction::iterator MBB, MBBE;
  MachineBasicBlock::iterator MBBI, MBBIE;
  MachineInstrBuilder  MIB;
  MachineInstr *MI;
  std::vector<llvm::MachineInstr*> alreadyCheckedInstr;

  for (MBB = MF.begin(), MBBE = MF.end(); 
       MBB != MBBE; ++MBB){
    for (MBBI = MBB->begin(), MBBIE = MBB->end(); 
	 MBBI != MBBIE; ++MBBI) {

      MI = MBBI;

      if(MBB->empty())
	continue;

      if ( !( MI->isIndirectBranch() || isIndirectCall(MI) ) ) // If not jmp* nor call*
	continue;

      if( contains(alreadyCheckedInstr, MI) ) 
	continue;

      // errs()<<  "[!] Splitting for call*/jmp* in " << MF.getName() << 
      //   " MBB" << MBB->getNumber() << " : " << *MI;
      // errs() << *MBB;
      alreadyCheckedInstr.push_back(MI);

      // Do it nicely.
      MachineBasicBlock *newMBB = MF.CreateMachineBasicBlock();
      MachineBasicBlock *hltMBB = MF.CreateMachineBasicBlock();
	
      MF.insert(MBB, hltMBB);
      MF.insert(MBB, newMBB);
      newMBB->moveAfter(&*MBB); 
      hltMBB->moveAfter(&*MBB);   
	
      MIB = BuildMI(*hltMBB, hltMBB->begin(), 
		    hltMBB->begin()->getDebugLoc(), TII.get(X86::HLT));
	
      newMBB->splice(newMBB->begin(), &*MBB, MI, MBB->end());
	
      newMBB->transferSuccessorsAndUpdatePHIs(&*MBB);
      MBB->addSuccessor(hltMBB);
      MBB->addSuccessor(newMBB);
	
      DebugLoc DL = newMBB->begin()->getDebugLoc();
      MIB = BuildMI(*MBB, MBB->end(), DL, TII.get(X86::JE_1)).addMBB(newMBB); 
      MBB->addLiveIn(X86::EFLAGS);
      GFreeDEBUG(1, "> " << *MIB);
      
      MachineBasicBlock::iterator tmpMI = std::prev(MBB->end()); // JE_1
      MachineFunction::iterator tmpMBB = MBB; 

      // If the cookie check routine is not before JE, than
      // go backwards and push it down!
      if((MBB->size() < 6) ||
	 matchCheckCookieRoutine(std::prev(tmpMI)) != 0){ 	
	GFreeDEBUG(2, "[!] Look for the check block and push it down\n");
	int status;
	do{
	  status = matchCheckCookieRoutine(tmpMI);
	  if(status == -1){ // We scanned all the block but llvm folded the indirect call in a new MBB.
	    GFreeDEBUG(2, "[!] Branch was folded. ");
	    GFreeDEBUG(2, "Starting to look our instructions from the end of prev of MBB#" << (tmpMBB)->getNumber() << "\n");
	    tmpMBB = std::prev(tmpMBB);
	    tmpMI= std::prev(tmpMBB->end());
	  }
	  if(status == 1){
	    tmpMI=std::prev(tmpMI);
	  }
	}while(status != 0);
      }
      else{ // The check routine was not moved, and prev(tmpMI) is pop
	tmpMI = std::prev(tmpMI);
      }
      
      MachineInstr *PushMI = std::prev(tmpMI,4);
      MachineInstr *MovMI = std::prev(tmpMI,3); // MOV
      MachineInstr *XorMI = std::prev(tmpMI,2); // XOR
      MachineInstr *CmpMI = std::prev(tmpMI,1); // CMP
      MachineInstr *PopMI = std::prev(tmpMI,0); // CMP

      GFreeDEBUG(2, "[GF] From here: \n" << *PushMI << *MovMI  << *XorMI << *CmpMI << *PopMI
      		 << "[GF] Move down, close to the JMP\n");

      MachineOperand &CmpDestReg = CmpMI->getOperand(0);
      MachineOperand &CmpBaseReg = XorMI->getOperand(2);
      MachineOperand &CmpDisplacement = XorMI->getOperand(5);
      MachineBasicBlock::iterator insertPoint = std::prev(MBB->end());
	  
      assert(CmpDestReg.isReg() && "Is should be a register!");
      assert(CmpBaseReg.isReg() &&		 
	     CmpDisplacement.isImm() &&
	     "Displacement is not immediate in X86GFree.cpp");

      // If the cookie is referenced with RSP, we have to add 8 to the displacement because of the push.
      int offsetAdjustment = CmpBaseReg.getReg() == X86::RSP ? +8 : 0;
      CmpDisplacement.setImm(CmpDisplacement.getImm() + offsetAdjustment);

      PushMI->removeFromParent();
      PushMI->setDebugLoc(DL);
      MBB->insert(insertPoint, PushMI);

      MovMI->removeFromParent();
      MovMI->setDebugLoc(DL);
      MBB->insert(insertPoint, MovMI);

      XorMI->removeFromParent();
      XorMI->setDebugLoc(DL);
      MBB->insert(insertPoint, XorMI);

      CmpMI->removeFromParent();
      CmpMI->setDebugLoc(DL);
      MBB->insert(insertPoint, CmpMI);

      PopMI->removeFromParent();
      PopMI->setDebugLoc(DL);
      MBB->insert(insertPoint, PopMI);

      emitNop(MovMI, 9);

      GFreeDEBUG(3, "[GF] After splitting: \n" <<
		    " MBB: "    << *MBB        <<
		    " newMBB: " << *newMBB     <<
		    " hltMBB: " << *hltMBB     );
      break;
    }
  }
}

// Main.
bool GFreeMachinePass::runOnMachineFunction(MachineFunction &MF) {
  if(MF.empty())
    return true;

  returnAddressProtection(MF);
  cookieProtectionFinalization(MF);
  instructionTransformation(MF); 

  return true;

}
static RegisterPass<GFreeMachinePass> X("gfree", "My Machine Pass");

