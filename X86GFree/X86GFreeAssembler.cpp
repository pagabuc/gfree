

//===-- X86GFreeAssembler.cpp - Assemble X86 MachineInstr to bytes --------===//
//
//                     The LLVM Compiler Infrastructure
//
//===----------------------------------------------------------------------===//
//
// This file contains code to XXXXXX.
//
//===----------------------------------------------------------------------===//

#include <X86GFreeAssembler.h>


using namespace llvm;

GFreeAssembler::GFreeAssembler(MachineFunction &MF, VirtRegMap *VRMap){
  VRM=VRMap;
  STI = &MF.getSubtarget();
  TII = MF.getSubtarget().getInstrInfo();
  TRI = MF.getSubtarget().getRegisterInfo();

  // Create a temp MachineBasicBlock at the end of this function.  
  tmpMBB = MF.CreateMachineBasicBlock();
  MF.insert(MF.end(), tmpMBB);

  const TargetMachine &TM = MF.getTarget();
  const Target &T = TM.getTarget();
  
  // Let's create a MCCodeEmitter
  CodeEmitter.reset(T.createMCCodeEmitter(
       *MF.getSubtarget().getInstrInfo(), 
       *MF.getSubtarget().getRegisterInfo(),
       MF.getContext() 			  ));

  // NullStreamer->reset(S);

  // let's create a TargetMachine for AsmPrinter
  // tmpTM = T.createTargetMachine(
  // 				TM.getTargetTriple(),
  // 				TM.getTargetCPU(),
  // 				TM.getTargetFeatureString(),
  // 				TM.Options);
  // const TargetMachine &tmpTM = MF.getTarget();

  // Let's create a (null) MCStreamer for AsmPrinter
  MCStreamer *NullStreamer = T.createNullStreamer(MF.getContext());

  // Let's create a X86AsmPrinter for MCInstLower
  std::unique_ptr<TargetMachine> tmpTM;
  tmpTM.reset(T.createTargetMachine(TM.getTargetTriple().getTriple(),
				 TM.getTargetCPU(),
				 TM.getTargetFeatureString(),
				 TM.Options));

  Printer = static_cast<X86AsmPrinter*>(T.createAsmPrinter(*tmpTM, std::unique_ptr<MCStreamer>(NullStreamer)));  
  Printer->setSubtarget(&MF.getSubtarget<X86Subtarget>());
  // Finally(!) create an X86MCInstLower object.
  MCInstLower = new X86MCInstLower(MF, *Printer);
}

GFreeAssembler::~GFreeAssembler(){
  // 6b.
  tmpMBB->erase(tmpMBB->begin(), tmpMBB->end());
  tmpMBB->eraseFromParent();
}

void GFreeAssembler::temporaryRewriteRegister(MachineInstr *MI){
  // errs() << "[+] TemporaryRewriteRegister!\n\n";
  MachineFunction *MF = MI->getParent()->getParent();
  const TargetRegisterInfo *TRI = MF->getRegInfo().getTargetRegisterInfo();
  unsigned int VirtReg, PhysReg;

  for(MachineOperand &MO: MI->operands()){
    if( MO.isReg() &&  TRI->isVirtualRegister(MO.getReg()) ){

      VirtReg = MO.getReg();
      PhysReg = VRM->getPhys(VirtReg);
      // Preserve semantics of sub-register operands.
      if (MO.getSubReg()) {
	// PhysReg operands cannot have subregister indexes, so allocate the right (sub) physical register.                            
	PhysReg = TRI->getSubReg(PhysReg, MO.getSubReg());
	assert(PhysReg && "Invalid SubReg for physical register");
	MO.setSubReg(0);
      }
      MO.setReg(PhysReg); // Rewriting.
    }
  }
  return;
}

std::vector<unsigned char> GFreeAssembler::lowerEncodeInstr(MachineInstr *RegRewMI){
  std::string ResStr;
  SmallVector<MCFixup, 4> Fixups;
  raw_string_ostream tmpRawStream(ResStr);

  MCInst OutMI;    

  // Lower.
  MCInstLower->Lower(RegRewMI,OutMI);  

  // Encode.
  CodeEmitter->encodeInstruction(OutMI, tmpRawStream, Fixups, *STI);
  tmpRawStream.flush();

  std::vector<unsigned char> MIbytes (ResStr.begin(), ResStr.end());
  return  MIbytes;
}


// This is somehow copied from ExpandPostRAPseudos.cpp 
bool GFreeAssembler::LowerCopy(MachineInstr *MI) {
  MachineOperand &DstMO = MI->getOperand(0);
  MachineOperand &SrcMO = MI->getOperand(1);

  // For now we don't support floating point instructions.
  if(DstMO.getReg() == X86::FP0 || DstMO.getReg() == X86::FP1 || DstMO.getReg() == X86::FP2 || DstMO.getReg() == X86::FP3 ||
     DstMO.getReg() == X86::FP4 || DstMO.getReg() == X86::FP5 || DstMO.getReg() == X86::FP6 || DstMO.getReg() == X86::FP7 )
    return false;
  
  if (MI->allDefsAreDead() ||
     (SrcMO.getReg() == DstMO.getReg()) ) { // copy the same reg.
    return false;
  }

  // errs() << "real copy!:  " << *MI;
  TII->copyPhysReg(*MI->getParent(), MI, MI->getDebugLoc(),
                   DstMO.getReg(), SrcMO.getReg(), SrcMO.isKill());

  MI->eraseFromParent();
  return true;
}

// This is somehow copied from ExpandPostRAPseudos.cpp
bool GFreeAssembler::LowerSubregToReg(MachineInstr *MI) {
  MachineBasicBlock *MBB = MI->getParent();
  
  assert((MI->getOperand(0).isReg() && MI->getOperand(0).isDef()) &&
         MI->getOperand(1).isImm() &&
         (MI->getOperand(2).isReg() && MI->getOperand(2).isUse()) &&
	 MI->getOperand(3).isImm() && "Invalid subreg_to_reg");
  unsigned DstReg  = MI->getOperand(0).getReg();
  unsigned InsReg  = MI->getOperand(2).getReg();
  assert(!MI->getOperand(2).getSubReg() && "SubIdx on physreg?");
  unsigned SubIdx  = MI->getOperand(3).getImm();
  assert(SubIdx != 0 && "Invalid index for insert_subreg");
  unsigned DstSubReg = TRI->getSubReg(DstReg, SubIdx);
  assert(TargetRegisterInfo::isPhysicalRegister(DstReg) &&
         "Insert destination must be in a physical register");
  assert(TargetRegisterInfo::isPhysicalRegister(InsReg) &&
         "Inserted value must be in a physical register");
  
  // GFreeDEBUG(dbgs() << "subreg: CONVERTING: " << *MI);  
  if (MI->allDefsAreDead() || DstSubReg == InsReg) {
    return false;
  }

  TII->copyPhysReg(*MBB, MI, MI->getDebugLoc(), DstSubReg, InsReg,
		   MI->getOperand(2).isKill());
  MBB->erase(MI);
  return true;  
}

// This is somehow copied from ExpandPostRAPseudos.cpp
// false means that nothing was changed, i.e. MI will be transformed in a KILL.
// true means that something was changed so we need to check this MI. 
// NOTE: MI is not valid anymore after this function. 
// Use the lowered one from tmpMBB->begin().
bool GFreeAssembler::expandPseudo(MachineInstr *MI){
  assert(MI->isPseudo() && "MI is not a pseudo!\n");
  if( TII->expandPostRAPseudo(MI) ){
    // errs() << "[+] MI pseudo lowered BY TTI: " << *(tmpMBB->begin());
    return true;
  }

  bool Changed = false;
  switch (MI->getOpcode()) {
  case TargetOpcode::SUBREG_TO_REG:
    Changed = LowerSubregToReg(MI);
    break;
  case TargetOpcode::COPY:
    Changed = LowerCopy(MI);
    break;
  }
  // errs() << "[+] MI pseudo lowered BY HAND: " << *(tmpMBB->begin());
  return Changed;
}

// Here's the plan:
// 1) Clone and insert MI into a tmp MBB (otherwise we can't lower pseudos)
// 2) Fake-allocation of registers
// 3) if MI is pseudo, expand it;
// 4) lower MI to MCInst and assemble
// 6a) delete the lowered-expandend-regallocated MI
// 6b) at the end delete the parent tmpMBB so the function is not altered.

std::vector<unsigned char> GFreeAssembler::MachineInstrToBytes(MachineInstr *MI) {
  GFreeDEBUG(3, "[A] MI                         : " << *MI);
  MachineFunction *MF = MI->getParent()->getParent();
  std::vector<unsigned char> bytes;
  // 1. Clone MI into a new instruction and insert into the temp MBB.
  MachineInstr* tmpMI = MF->CloneMachineInstr(MI);  
  tmpMBB->insertAfter(tmpMBB->begin(), tmpMI);
  
  // 2. Temporary rewrite the registers.
  if(VRM != nullptr){
    temporaryRewriteRegister(tmpMI);
  }

  GFreeDEBUG(3, "[A] MI reg-rewrited            : " << *tmpMI);
  
  // 3. We could be before the ExpandPostRAPseudos pass, so we need to expand
  // some pseudos.
  if(tmpMI->isPseudo()){
    if(!expandPseudo(tmpMI) ){ // If we didn't expanded, return empty array.
      goto exit;
    }
    tmpMI = tmpMBB->begin();
  }
  GFreeDEBUG(3, "[A] MI rewrited-expanded       : " << *tmpMI);
  // 4. Lower and Encode MI.
  bytes = lowerEncodeInstr(tmpMI);
  GFreeDEBUG(3, "[A] MI rewrited-expaned-lowered: " << *tmpMI);
  GFreeDEBUG(3, "[A] MI assembled               : [ ");
  for ( unsigned char c: bytes)
    GFreeDEBUG(3, format("%02x", c));
  GFreeDEBUG(3," ]\n");

 exit:
  // 6a. Empty the MBB.
  tmpMBB->erase(tmpMBB->begin(), tmpMBB->end());
  return bytes;

  // [FIXME]: Since the pseudo expansion could produce more than 1 istruction,
  // we should process all of them, while now we process just the first.  Uncomment
  // this and clang -O2 diff-O3-file6GGqDq.c 
  
  // assert(tmpMBB->empty() && "tmpMBBis not empty!");
  
}

