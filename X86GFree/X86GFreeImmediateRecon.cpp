#include "llvm/Support/Format.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "X86Subtarget.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "X86GFreeUtils.h"
#include "X86.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/ADT/Statistic.h"

using namespace llvm;

//  Then, on the command line, you can specify '-debug-only=foo'
#define DEBUG_TYPE "gfreeimmediaterecon"
STATISTIC(EvilImm , "Number of immediate that contains c2/c3/ca/cb/ff");

namespace {
  class GFreeImmediateReconPass : public MachineFunctionPass {
  public:
    GFreeImmediateReconPass() : MachineFunctionPass(ID) {}
    bool runOnMachineBasicBlock();
    bool runOnMachineFunction(MachineFunction &mf){
      MF = &mf;
      STI = &MF->getSubtarget<X86Subtarget>();
      TII = MF->getSubtarget().getInstrInfo();
      MachineFunction::iterator MBBI, MBBE;
      for (MBBI = MF->begin(), MBBE = MF->end(); MBBI != MBBE; ++MBBI){
	MBB = &*MBBI;
	runOnMachineBasicBlock();
      }
      return true;
    }
    const char *getPassName() const override {return "Immediate Reconstruction Pass";}
    static char ID;
  private:
    unsigned int loadImmediateIntoVirtReg(MachineInstr *MI, std::pair<int64_t, int64_t> split, 
    					  int ImmediateIndex, int size, int* counter);
    void emitAddInstSubRegToReg(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg, 
    				unsigned int BaseRegIndex, unsigned int OffsetIndex);
    void emitNewInstructionMItoMR(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg);
    void emitNewInstructionRItoRR(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg);
    MachineFunction *MF;
    MachineBasicBlock *MBB;
    const X86Subtarget *STI;
    const TargetInstrInfo *TII;
  };
  char GFreeImmediateReconPass::ID = 0;
  
}

FunctionPass *llvm::createGFreeImmediateReconPass() {
  return new GFreeImmediateReconPass();
}

// This tables contains, for each instruction that could potentially host an
// evil byte in the immediate or in the offset, the new opcode and the size of
// the operand. 
std::map<unsigned int,std::pair<unsigned int, int>> RItoRR_opcodeMap {
  { X86::ADC8ri, {X86::ADC8rr, 8} },
  { X86::ADC16ri8, {X86::ADC16rr, 16}},
  { X86::ADC16ri, {X86::ADC16rr, 16}},
  { X86::ADC32ri, {X86::ADC32rr, 32}},
  { X86::ADC32ri8,{X86::ADC32rr,32}},
  { X86::ADC64ri32,{X86::ADC64rr,64}},
  { X86::ADC64ri8,{X86::ADC64rr,64}},

  { X86::ADD8ri,       {X86::ADD8rr,8}      },
  { X86::ADD16ri8,     {X86::ADD16rr,16}     },
  { X86::ADD16ri,      {X86::ADD16rr,16}     },
  { X86::ADD16ri_DB,   {X86::ADD16rr_DB,16}  },
  { X86::ADD16ri8_DB,  {X86::ADD16rr_DB,16}  },
  { X86::ADD32ri,      {X86::ADD32rr,32}    },
  { X86::ADD32ri8,     {X86::ADD32rr,32}    },
  { X86::ADD32ri_DB,   {X86::ADD32rr_DB,32} },
  { X86::ADD32ri8_DB,  {X86::ADD32rr_DB,32} },
  { X86::ADD64ri8,     {X86::ADD64rr,64}    },
  { X86::ADD64ri32,    {X86::ADD64rr,64}    },
  { X86::ADD64ri8_DB,  {X86::ADD64rr_DB,64} },
  { X86::ADD64ri32_DB, {X86::ADD64rr_DB,64} },

  { X86::SBB8ri,{X86::SBB8rr,8}},
  { X86::SBB16ri,{X86::SBB16rr,16}},
  { X86::SBB16ri8,{X86::SBB16rr,16}},
  { X86::SBB32ri,{X86::SBB32rr,32}},
  { X86::SBB32ri8,{X86::SBB32rr,32}},
  { X86::SBB64ri32,{X86::SBB64rr,64}},
  { X86::SBB64ri8,{X86::SBB64rr,64}},

  { X86::SUB8ri,{X86::SUB8rr,8}},
  { X86::SUB16ri,{X86::SUB16rr,16}},
  { X86::SUB16ri8,{X86::SUB16rr,16}},
  { X86::SUB32ri,{X86::SUB32rr,32}},
  { X86::SUB32ri8,{X86::SUB32rr,32}},
  { X86::SUB64ri32,{X86::SUB64rr,64}},
  { X86::SUB64ri8,{X86::SUB64rr,64}},

  { X86::OR8ri,{X86::OR8rr,8}},
  { X86::OR16ri,{X86::OR16rr,16}},
  { X86::OR16ri8,{X86::OR16rr,16}},
  { X86::OR32ri,{X86::OR32rr,32}},
  { X86::OR32ri8,{X86::OR32rr,32}},
  { X86::OR64ri32,{X86::OR64rr,64}},
  { X86::OR64ri8,{X86::OR64rr,64}},

  { X86::XOR8ri,{X86::XOR8rr,8}},
  { X86::XOR16ri,{X86::XOR16rr,16}},
  { X86::XOR16ri8,{X86::XOR16rr,16}},
  { X86::XOR32ri,{X86::XOR32rr,32}},
  { X86::XOR32ri8,{X86::XOR32rr,32}},
  { X86::XOR64ri32,{X86::XOR64rr,64}},
  { X86::XOR64ri8,{X86::XOR64rr,64}},

  { X86::AND8ri,{X86::AND8rr,8}},
  { X86::AND16ri,{X86::AND16rr,16}},
  { X86::AND16ri8,{X86::AND16rr,16}},
  { X86::AND32ri,{X86::AND32rr,32}},
  { X86::AND32ri8,{X86::AND32rr,32}},
  { X86::AND64ri32,{X86::AND64rr,64}},
  { X86::AND64ri8,{X86::AND64rr,64}},

  { X86::CMP8ri,{X86::CMP8rr,8}},
  { X86::CMP16ri,{X86::CMP16rr,16}},
  { X86::CMP16ri8,{X86::CMP16rr,16}},
  { X86::CMP32ri,{X86::CMP32rr,32}},
  { X86::CMP32ri8,{X86::CMP32rr,32}},
  { X86::CMP64ri32,{X86::CMP64rr,64}},
  { X86::CMP64ri8,{X86::CMP64rr,64}},

  { X86::MOV8ri,{X86::MOV8rr,8}},
  { X86::MOV16ri,{X86::MOV16rr,16}},
  { X86::MOV32ri,{X86::MOV32rr,32}},
  { X86::MOV32ri64,{X86::MOV32rr,32}},
  { X86::MOV64ri32,{X86::MOV64rr,64}},
  { X86::MOV64ri,{X86::MOV64rr,64}},

  { X86::TEST8i8, {X86::TEST8rr, 8}},
  { X86::TEST16i16, {X86::TEST16rr, 16}},
  { X86::TEST32i32, {X86::TEST32rr, 32}},
  { X86::TEST64i32, {X86::TEST64rr, 64}},
  { X86::TEST8ri, {X86::TEST8rr, 8}},
  { X86::TEST16ri, {X86::TEST16rr, 16}},
  { X86::TEST32ri, {X86::TEST32rr, 32}},
  { X86::TEST64ri32, {X86::TEST64rr, 64}}
};

std::map<unsigned int,std::pair<unsigned int, int>> MItoMR_opcodeMap {
  {X86::ADC32mi,{X86::ADC32mr,32}},
  {X86::ADC32mi8,{X86::ADC32mr,32}},
  {X86::ADC64mi32,{X86::ADC64mr,64}},
  {X86::ADC64mi8,{X86::ADC64mr,64}},

  {X86::ADD8mi,{X86::ADD8mr,8}},
  {X86::ADD16mi8,{X86::ADD16mr,16}},
  {X86::ADD16mi,{X86::ADD16mr,16}},
  {X86::ADD32mi8,{X86::ADD32mr,32}},
  {X86::ADD32mi,{X86::ADD32mr,32}},
  {X86::ADD64mi8,{X86::ADD64mr,64}},
  {X86::ADD64mi32,{X86::ADD64mr,64}},

  {X86::SBB8mi,{X86::SBB8mr,8}},
  {X86::SBB16mi8,{X86::SBB16mr,16}},
  {X86::SBB16mi,{X86::SBB16mr,16}},
  {X86::SBB32mi8,{X86::SBB32mr,32}},
  {X86::SBB32mi,{X86::SBB32mr,32}},
  {X86::SBB64mi8,{X86::SBB64mr,64}},
  {X86::SBB64mi32,{X86::SBB64mr,64}},

  {X86::SUB8mi,{X86::SUB8mr,8}},
  {X86::SUB16mi8,{X86::SUB16mr,16}},
  {X86::SUB16mi,{X86::SUB16mr,16}},
  {X86::SUB32mi8,{X86::SUB32mr,32}},
  {X86::SUB32mi,{X86::SUB32mr,32}},
  {X86::SUB64mi8,{X86::SUB64mr,64}},
  {X86::SUB64mi32,{X86::SUB64mr,64}},

  {X86::OR8mi,{X86::OR8mr,8}},
  {X86::OR16mi8,{X86::OR16mr,16}},
  {X86::OR16mi,{X86::OR16mr,16}},
  {X86::OR32mi8,{X86::OR32mr,32}},
  {X86::OR32mi,{X86::OR32mr,32}},
  {X86::OR64mi8,{X86::OR64mr,64}},
  {X86::OR64mi32,{X86::OR64mr,64}},

  {X86::XOR8mi,{X86::XOR8mr,8}},
  {X86::XOR16mi8,{X86::XOR16mr,16}},
  {X86::XOR16mi,{X86::XOR16mr,16}},
  {X86::XOR32mi8,{X86::XOR32mr,32}},
  {X86::XOR32mi,{X86::XOR32mr,32}},
  {X86::XOR64mi8,{X86::XOR64mr,64}},
  {X86::XOR64mi32,{X86::XOR64mr,64}},

  {X86::AND8mi,{X86::AND8mr,8}},
  {X86::AND16mi8,{X86::AND16mr,16}},
  {X86::AND16mi,{X86::AND16mr,16}},
  {X86::AND32mi8,{X86::AND32mr,32}},
  {X86::AND32mi,{X86::AND32mr,32}},
  {X86::AND64mi8,{X86::AND64mr,64}},
  {X86::AND64mi32,{X86::AND64mr,64}},

  {X86::CMP8mi,{X86::CMP8mr,8}},
  {X86::CMP16mi8,{X86::CMP16mr,16}},
  {X86::CMP16mi,{X86::CMP16mr,16}},
  {X86::CMP32mi8,{X86::CMP32mr,32}},
  {X86::CMP32mi,{X86::CMP32mr,32}},
  {X86::CMP64mi8,{X86::CMP64mr,64}},
  {X86::CMP64mi32,{X86::CMP64mr,64}},

  {X86::MOV8mi,{X86::MOV8mr,8}},
  {X86::MOV16mi,{X86::MOV16mr,16}},
  {X86::MOV32mi,{X86::MOV32mr,32}},
  {X86::MOV64mi32,{X86::MOV64mr,64}},
};

// This maps are incomplete, but cover the compilation of some real-world program.
std::map<unsigned int,std::pair<unsigned int, int>> RMtoRM_opcodeMap {
  {X86::MOVSX32rm8,{X86::MOVSX32rm8,64}},
  {X86::MOVSX64rm16,{X86::MOVSX64rm16,64}},
  {X86::MOVZX32rm8,{X86::MOVZX32rm8,64}},
  {X86::MOV8rm,{X86::MOV8rm,64}},
  {X86::MOV16rm,{X86::MOV16rm,64}},
  {X86::MOV32rm,{X86::MOV32rm,64}},
  {X86::MOV64rm,{X86::MOV64rm,64}},
};

std::map<unsigned int,std::pair<unsigned int, int>> MRtoMR_opcodeMap {
  {X86::MOV8mr,{X86::MOV8mr,64}},
  {X86::MOV16mr,{X86::MOV16mr,64}},
  {X86::MOV32mr,{X86::MOV32mr,64}},
  {X86::MOV64mr,{X86::MOV64mr,64}},
};

std::map<unsigned int,std::pair<unsigned int, int>> LEA_opcodeMap {
  {X86::LEA64_32r,{X86::LEA64_32r,64}},
  {X86::LEA16r,{X86::LEA16r,64}},
  {X86::LEA32r,{X86::LEA32r,64}},
  {X86::LEA64r,{X86::LEA64r,64}},
};

bool isRI(unsigned int Opcode){
  return (RItoRR_opcodeMap[Opcode].first != 0);
}

bool isMI(unsigned int Opcode){
  return (MItoMR_opcodeMap[Opcode].first != 0);
}

bool isMR(unsigned int Opcode){
  return (MRtoMR_opcodeMap[Opcode].first != 0);
}

bool isRM(unsigned int Opcode){
  return (RMtoRM_opcodeMap[Opcode].first != 0);
}

bool isLEA(unsigned int Opcode){
  return (LEA_opcodeMap[Opcode].first != 0);
}

unsigned int getOpcodeFromMaps(unsigned int Opcode){
  return (RItoRR_opcodeMap[Opcode].first | 
	  MItoMR_opcodeMap[Opcode].first |
	  RMtoRM_opcodeMap[Opcode].first |
	  MRtoMR_opcodeMap[Opcode].first |
	  LEA_opcodeMap[Opcode].first 
	  );
}

unsigned int getSizeFromMaps(unsigned int Opcode){
  return (RItoRR_opcodeMap[Opcode].second | 
	  MItoMR_opcodeMap[Opcode].second |
	  RMtoRM_opcodeMap[Opcode].second |
	  MRtoMR_opcodeMap[Opcode].second |
	  LEA_opcodeMap[Opcode].second 
	  );
}

// Given a RI instruction and a register (ImmReg) that contains the immediate,
// this function translate the evil RI instruction into a safe RR instruction.
void GFreeImmediateReconPass::emitNewInstructionRItoRR(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg){
  MachineBasicBlock::iterator MBBI = MI;
  MachineInstrBuilder MIB;

  bool isMoveCompareTest = isMove(MI) || isCompare(MI) || isTest(MI);
  unsigned int DestReg = MI->getOperand(0).getReg();
  unsigned int SrcRegIndex = isMoveCompareTest ? 0 : 1;
  unsigned int SrcReg = MI->getOperand(SrcRegIndex).getReg();
  
  if ( isMoveCompareTest ) { // Handle MOV, CMP and TEST.
    unsigned int flags = isMove(MI) ? RegState::Define : 0;
    MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(NewOpcode))
      .addReg(DestReg, flags)
      .addReg(ImmReg);	
  }
  else {                     // Handle Arithm: XOR, OR, ADD ...
    MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(NewOpcode))
      .addReg(DestReg, RegState::Define)
      .addReg(SrcReg)
      .addReg(ImmReg);
  }
  GFreeDEBUG(0, "> " << *MIB);  
}

// Given a MI instruction and a register (ImmReg) that contains the immediate,
// this function translate the evil MI instruction into a safe MR instruction.
void GFreeImmediateReconPass::emitNewInstructionMItoMR(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg){
  MachineInstrBuilder MIB;
  MachineBasicBlock::iterator MBBI = MI;

  MI->RemoveOperand(5); // The fifth operand is the immediate.
  MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(NewOpcode)); 
  for (const MachineOperand &MO : MI->operands()) { // Copy all the operands   
    MIB.addOperand(MO);
  }
  MIB.addReg(ImmReg);
  GFreeDEBUG(0, "> " << *MIB); 	    
}

// This function deals with evil offsets. 
// ImmReg is a register that contains the offset. 
// It does emit 3 new instructions:
// ADD ImmReg, BaseReg
// INST (w/ offset = 0)
// SUB ImmReg, BaseReg
void GFreeImmediateReconPass::emitAddInstSubRegToReg(MachineInstr *MI, unsigned int NewOpcode, unsigned int ImmReg, 
						     unsigned int BaseRegIndex, unsigned int OffsetIndex){
  
  MachineBasicBlock::iterator MBBI = MI;
  MachineInstrBuilder MIB;

  // The size is always 8 bytes, since we are dealing with memory.
  unsigned int size = 8;
  const TargetRegisterClass *RegClass = getRegClassFromSize(size);
  unsigned int SumReg = MF->getRegInfo().createVirtualRegister(RegClass);
  unsigned int SubReg = MF->getRegInfo().createVirtualRegister(RegClass);
  unsigned int SrcReg = MI->getOperand(BaseRegIndex).getReg();

  // ADD
  MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getADDrrOpcode(size)))
    .addReg(SumReg, RegState::Define)
    .addReg(SrcReg)
    .addReg(ImmReg);	
  GFreeDEBUG(0, "> " << *MIB); 

  MachineInstr *newMI = MF->CloneMachineInstr(MI);
  MBB->insert(MBBI, newMI);
  
  // Adjust operands of the new instruction
  newMI->getOperand(BaseRegIndex).setReg(SumReg);
  newMI->getOperand(BaseRegIndex).setIsKill(false); // Clear kill flag because it's used by SUB
  newMI->getOperand(OffsetIndex).setImm(0);
  GFreeDEBUG(0, "> " << *newMI);    

  // SUB
  MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getSUBrrOpcode(size)))
    .addReg(SubReg, RegState::Define)
    .addReg(SumReg)
    .addReg(ImmReg);	
  GFreeDEBUG(0, "> " << *MIB);
}

// This function safely load an evil immediate into a new register.
// It returns the number of the new register.
unsigned int GFreeImmediateReconPass::loadImmediateIntoVirtReg(MachineInstr *MI, std::pair<int64_t, int64_t> split,
							       int ImmediateIndex, int size, int* counter){
  MachineInstrBuilder MIB;
  MachineBasicBlock::iterator MBBI = MI;

  size = size / 8;
  const TargetRegisterClass *RegClass = getRegClassFromSize(size);
  unsigned int NewReg = MF->getRegInfo().createVirtualRegister(RegClass);
  unsigned int ImmReg = MF->getRegInfo().createVirtualRegister(RegClass);

  MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getMOVriOpcode(size))) // MOV the big part.
    .addReg(NewReg, RegState::Define)
    .addImm(split.second);
  GFreeDEBUG(0, "> " << *MIB); 	    

  if((uint64_t)split.first <= 0xffffffff){ // if the small part fits in 32bit then we can do mov + or.
    MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getORriOpcode(size))) // OR the small part.
      .addReg(ImmReg, RegState::Define)
      .addReg(NewReg)
      .addImm(split.first); 	    
    GFreeDEBUG(0, "> " << *MIB);
    *counter = 2;
  }
  else{ // else do mov + mov + or
    unsigned int NewReg1 = MF->getRegInfo().createVirtualRegister(RegClass);
    MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getMOVriOpcode(size))) // MOV the high part.
      .addReg(NewReg1, RegState::Define)
      .addImm(split.first); 	    
    GFreeDEBUG(0, "> " << *MIB);
    
    MIB = BuildMI(*MBB, MBBI, MI->getDebugLoc(), TII->get(getORrrOpcode(size))) // OR the two new registers.
      .addReg(ImmReg, RegState::Define)
      .addReg(NewReg)
      .addReg(NewReg1);
    GFreeDEBUG(0, "> " << *MIB);
    *counter = 3;
  }
  return ImmReg;
}

// Main.
bool GFreeImmediateReconPass::runOnMachineBasicBlock() {
  
  if(DisableGFree){
    errs()<< "GFREE IS DISABLED!\n";
    return true;
  }

  if(MF->empty())
    return true;

  MachineBasicBlock::iterator MBBI, MBBIE;
  MachineInstrBuilder MIB;
  
  std::vector<MachineInstr*> toDelete; // This hold all the instructions that will be deleted.
  MachineInstr *MI;
  unsigned int i;
  std::pair<int64_t, int64_t> split;
  bool pushEFLAGS;
  
  for (MBBI = MBB->begin(), MBBIE = MBB->end(); MBBI != MBBIE; ++MBBI) {
    MI = MBBI;

    for(i=0; i<MI->getNumOperands(); i++){
      MachineOperand MO = MI->getOperand(i);
      if (!MO.isImm())
	continue;

      unsigned int NewOpcode = getOpcodeFromMaps(MI->getOpcode());
      unsigned int Size = getSizeFromMaps(MI->getOpcode());

      if(isMI(MI->getOpcode()) && i == 3) Size = 64; // When MI and offset, size must be 8;
      if(Size == 0) Size=64; // This is useful so we pass the next if and can print the TODO.

      split = splitInt(MO.getImm(),Size);
      bool found =  (split.first != 0 || split.second!=0);
      if( !found ){  
	continue;
      }

      /* TODO: The problem with <fi#>s is that they are translated after the stack
	 allocation, and the offset changes. We have to handle this at the end of
	 the pass chain. */
      if ( (isMI(MI->getOpcode()) && MI->getOperand(0).isFI() && i==3) ||
	   // This happens when compiling firefox, why?!
	   (isMI(MI->getOpcode()) && i == 3 && MI->getOperand(0).isReg() && MI->getOperand(0).getReg() == 0) || 
 	   (isRM(MI->getOpcode()) && MI->getOperand(1).isFI()) ||
	   (isMR(MI->getOpcode()) && MI->getOperand(0).isFI()) ||
	   (isLEA(MI->getOpcode()) && MI->getOperand(1).isFI())||
	   // ./compile-O3-fileU9CBCR.c
	   (isLEA(MI->getOpcode()) && MI->getOperand(1).getReg() == 0)||
	   (NewOpcode == 0)                                    ){ 
      	GFreeDEBUG(0, "[TODO @ " << MF->getName() << "]: " << *MI);
      	continue;
      }

      pushEFLAGS = needToSaveEFLAGS(MBBI); 

      ++EvilImm; // Update stats

      GFreeDEBUG(0, "[!] Found instruction with evil immediate @ " 
		 << MF->getName() << " BB#" << MBB->getNumber() << " : " << *MI  << "\n");
      GFreeDEBUG(2, "[IMM]       : " << format("0x%016llx @ %s \n", MO.getImm(), MF->getName() ) <<
                    "[IMM]       : " << format("(low = 0x%016llx, high = 0x%016llx)\n", split.first, split.second));

      toDelete.push_back(MI);
      GFreeDEBUG(0, "< " << *MI); 	    

      int emittedInstCounter = 0; // This counter will be used for the handling EFLAGS
      unsigned int ImmReg = loadImmediateIntoVirtReg(MI, split, i, Size,&emittedInstCounter);
      bool flagImmediate=0;

      // Immediates.
      if(isRI(MI->getOpcode())){
      	emitNewInstructionRItoRR(MI, NewOpcode, ImmReg);
	flagImmediate = 1;
      }

      if(isMI(MI->getOpcode()) && i == 5){ // 5 is the index of an immediate in a *mi instruction.
      	emitNewInstructionMItoMR(MI, NewOpcode, ImmReg);
	flagImmediate = 1;
      }

      // Offsets.
      if(isMI(MI->getOpcode()) && i == 3){ // 3 is the index of an offset in a *mi instruction.
      	emitAddInstSubRegToReg(MI, NewOpcode, ImmReg, 0, i);
      }
      if(isLEA(MI->getOpcode())){
      	MI->clearKillInfo();
      	emitAddInstSubRegToReg(MI, NewOpcode, ImmReg, 1, i);      
      }
      if(isRM(MI->getOpcode())){
      	emitAddInstSubRegToReg(MI, NewOpcode, ImmReg, 1, i);
      }
      if(isMR(MI->getOpcode())){
      	emitAddInstSubRegToReg(MI, NewOpcode, ImmReg, 0, i);
      }

      // Erase the old instruction and update iterators. At this point
      // MBBI still points to the original MI.
      MachineInstr *NewMI;
      if(flagImmediate){
	NewMI = std::prev(MBBI); 
	MBBI = NewMI;
      }
      else{
	NewMI = std::prev(MBBI,2); // Skips the sub.
	MBBI = std::prev(MBBI); // Points to the sub.
      }
      MI->eraseFromParent();

      // EFLAGS handling.
      
      /* 
	 If we handled an immediate the layout can be:
	 mov, or, newMI <-- MBBI, (deleted MI) (emittedInstCounter =  2) otherwise
	 mov, mov, or, newMI <-- MBBI, (deleted MI) (emittedInstCounter =  3) 
	 
	 If we handled an offset the layout can be:
	 mov, or, add, newMI, sub <-- MBBI, (deleted MI) (emittedInstCounter =  2) otherwise 
	 mov, mov, or, add, newMI, sub <-- MBBI, (deleted MI) (emittedInstCounter =  3) 
      */


      if( std::next(MBBI) == MBB->end() ) // newMI/SUB is the last instruction of this MBB, check in the next MBB.
	pushEFLAGS = needToSaveEFLAGS( (*MBB->succ_begin())->begin() );
      else
	pushEFLAGS = needToSaveEFLAGS(std::next(MBBI));

      if( !pushEFLAGS ) continue;

      GFreeDEBUG(0, "> Push/Pop EFLAGS\n");	
      unsigned int saveRegEFLAGS = MF->getRegInfo().createVirtualRegister(&X86::GR64RegClass);
      
      if(flagImmediate){ 
	pushEFLAGSinline( std::prev(MBBI,emittedInstCounter), saveRegEFLAGS ); // Before the first mov
	popEFLAGSinline ( MBBI, saveRegEFLAGS ); // Before newMI
	continue;
      }

      bool useEFLAGS = NewMI->readsRegister(X86::EFLAGS);
      bool defineEFLAGS = NewMI->definesRegister(X86::EFLAGS);

      if(!defineEFLAGS && !useEFLAGS){  // i.e. LEA
	pushEFLAGSinline( std::prev(MBBI,2+emittedInstCounter),saveRegEFLAGS ); // Before first mov
	popEFLAGSinline ( std::next(MBBI), saveRegEFLAGS ); // After sub;		
      }
      else if(!defineEFLAGS && useEFLAGS){ // i.e. CMOV
	pushEFLAGSinline( std::prev(MBBI,2+emittedInstCounter), saveRegEFLAGS ); // Before first mov
	popEFLAGSinline( std::prev(MBBI), saveRegEFLAGS ); // Before newMI

	pushEFLAGSinline ( MBBI, saveRegEFLAGS ); // Before sub;
	popEFLAGSinline ( std::next(MBBI), saveRegEFLAGS ); // After sub;	
      }
      else if(defineEFLAGS && !useEFLAGS){ // i.e. CMP
	pushEFLAGSinline ( MBBI, saveRegEFLAGS ); // Before sub;
	popEFLAGSinline ( std::next(MBBI), saveRegEFLAGS ); // After sub;	
      }
      else if(defineEFLAGS && useEFLAGS){ // i.e. ADC 
	pushEFLAGSinline( std::prev(MBBI,2+emittedInstCounter), saveRegEFLAGS ); // Before first mov
	popEFLAGSinline( std::prev(MBBI), saveRegEFLAGS ); // Before newMI
      }
    }
  }  
  return true;
}

static RegisterPass<GFreeImmediateReconPass> X("gfreeimmediaterecon", "My Machine Pass");

  // Deleting instructions.
  // for (std::vector<MachineInstr*>::iterator  I = toDelete.begin(); I != toDelete.end(); ++I){
  //   (*I)->eraseFromParent();
  // }
