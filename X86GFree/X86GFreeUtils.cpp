#include "X86GFreeUtils.h"
#include "X86.h"
#include "X86Subtarget.h"
#include <iomanip>
#include <utility>
#include "llvm/Support/Format.h"
#include "X86InstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

cl::opt<bool>  DisableGFree("disable-gfree", cl::Hidden,
	       cl::desc("Disable GFree protections"));

/* Global Variables*/

int getORrrOpcode(unsigned int size){
  if( size == 1 ){
    return X86::OR8rr;
  }
  if( size == 2 ){
    return X86::OR16rr;
  }
  if( size == 4 ){
    return X86::OR32rr;
  }
  if( size == 8 ){
    return X86::OR64rr;
  }
  assert(false && "[getORopcode] We should never get here!");
  return 0;
}

int getMOVriOpcode(unsigned int size){
  if( size == 1 ){
    return X86::MOV8ri;
  }
  if( size == 2 ){
    return X86::MOV16ri;
  }
  if( size == 4 ){
    return X86::MOV32ri;
  }
  if( size == 8 ){
    return X86::MOV64ri;
  }
  assert(false && "[getMOVopcode] We should never get here!");
  return 0;
}

int getADDrrOpcode(unsigned int size){
  if( size == 1 ){
    return X86::ADD8rr;
  }
  if( size == 2 ){
    return X86::ADD16rr;
  }
  if( size == 4 ){
    return X86::ADD32rr;
  }
  if( size == 8 ){
    return X86::ADD64rr;
  }
  assert(false && "[getADDopcode] We should never get here!");
  return 0;
}

int getSUBrrOpcode(unsigned int size){
  if( size == 1 ){
    return X86::SUB8rr;
  }
  if( size == 2 ){
    return X86::SUB16rr;
  }
  if( size == 4 ){
    return X86::SUB32rr;
  }
  if( size == 8 ){
    return X86::SUB64rr;
  }
  assert(false && "[getSUBopcode] We should never get here!");
  return 0;
}

int getORriOpcode(unsigned int size){
  if( size == 1 ){
    return X86::OR8ri;
  }
  if( size == 2 ){
    return X86::OR16ri;
  }
  if( size == 4 ){
    return X86::OR32ri;
  }
  if( size == 8 ){
    return X86::OR64ri32;
  }

  assert(false && "[getORopcode] We should never get here!");
  return 0;
}


// python listcalljmpstar.py
int values_to_avoid[] = {0x10,0x11,0x12,0x13,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1e,
			 0x1f,0x20,0x21,0x22,0x23,0x26,0x27,0x28,0x29,0x2a,0x2b,
			 0x2e,0x2f,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xe0,
			 0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7};
bool FFblacklist(int I){
  return std::find(std::begin(values_to_avoid), std::end(values_to_avoid), I) != std::end(values_to_avoid);
}

std::pair<int64_t, int64_t> splitInt(int64_t Imm, int Size){
  std::pair <int64_t, int64_t> p(0,0);
  int64_t low = 0;  
  for(int shift = 0; shift <= Size -8; shift+=8){
    int64_t current_byte = (Imm >> shift ) & 0xFF; // (0xffc3ff >> 8) && 0xff == 0xc3 
    int64_t next;
    if(shift == Size - 8) 
      next = 0; // next of MSB is outside this instruction, so set it to 0.
    else
      next = ( Imm >> (shift + 8) ) & 0xFF;
    // errs() << format("%d, current=0x%02llx, next=0x%02llx\n",shift, current_byte, next);
    if ( current_byte == 0xc2 || current_byte == 0xc3 || 
	 current_byte == 0xca || current_byte == 0xcb ||
         (current_byte == 0xff && FFblacklist(next))  ){
      // Found a ret in the immediate.
      current_byte = current_byte & 0x0f; // == 0x3
      low |= (current_byte << shift); //  low  |= 0x000300      
    }
  }
  if (low == 0) // We didn't found anything.
    return p;
  
  p.first = std::min(low,Imm & (~low));
  p.second = std::max(low,Imm & (~low));
  return p;
}


bool isIndirectCall(MachineInstr *MI){
  switch(MI->getOpcode()) {
  case X86::CALL16r:
  case X86::CALL32r:
  case X86::CALL64r:
  case X86::CALL16m:
  case X86::CALL32m:
  case X86::CALL64m:
  case X86::FARCALL16m:
  case X86::FARCALL32m:
  case X86::FARCALL64:
  case X86::TAILJMPr64:
  case X86::TAILJMPm64:
  case X86::TCRETURNri64:
  case X86::TCRETURNmi64:
    return true;

  default: return false;
  }
}

bool contains(std::vector<llvm::MachineInstr*> v, MachineInstr* mbb){
  return std::find(std::begin(v), std::end(v), mbb) != std::end(v);
}

bool isMove(MachineInstr *MI){
  switch(MI->getOpcode()) {
  default: 
    return 0;
  case X86::MOV8ri:
  case X86::MOV16ri:
  case X86::MOV32ri:
  case X86::MOV32ri64:
  case X86::MOV64ri32:
  case X86::MOV64ri:
  case X86::MOV8mi:
  case X86::MOV16mi:
  case X86::MOV32mi:
  case X86::MOV64mi32:
    return 1;
  }
}

bool isArithmUsesEFLAGS(MachineInstr *MI){
  switch(MI->getOpcode()) {
  default: 
    return 0;
  case X86::ADC8ri:
  case X86::ADC16ri8:
  case X86::ADC16ri:
  case X86::ADC32ri:
  case X86::ADC32ri8:
  case X86::ADC64ri32:
  case X86::ADC64ri8:
  case X86::SBB8ri:
  case X86::SBB16ri:
  case X86::SBB16ri8:
  case X86::SBB32ri:
  case X86::SBB32ri8:
  case X86::SBB64ri32:
  case X86::SBB64ri8:
  case X86::SBB8mi:
  case X86::SBB16mi8:
  case X86::SBB16mi:
  case X86::SBB32mi8:
  case X86::SBB32mi:
  case X86::SBB64mi8:
  case X86::SBB64mi32:
  case X86::ADC32mi:
  case X86::ADC32mi8:
  case X86::ADC64mi32:
  case X86::ADC64mi8:
    return 1;
  }
}

bool isTest(MachineInstr *MI){
  switch(MI->getOpcode()) {
  default: 
    return 0;

  case X86::TEST8i8:
  case X86::TEST8ri:
  case X86::TEST16i16:
  case X86::TEST16ri:
  case X86::TEST32i32:
  case X86::TEST32ri:
  case X86::TEST64i32:
  case X86::TEST64ri32:
  // case X86::TEST8mi:
  // case X86::TEST16mi:
  // case X86::TEST32mi:
  // case X86::TEST64mi32:
    return 1;
  }
}

bool isCompare(MachineInstr *MI){
  switch(MI->getOpcode()) {
  default: 
    return 0;

  case X86::CMP8ri:
  case X86::CMP16ri:
  case X86::CMP16ri8:
  case X86::CMP32ri:
  case X86::CMP32ri8:
  case X86::CMP64ri32:
  case X86::CMP64ri8:
  case X86::CMP8mi:
  case X86::CMP16mi:
  case X86::CMP16mi8:
  case X86::CMP32mi:
  case X86::CMP32mi8:
  case X86::CMP64mi32:
  case X86::CMP64mi8:
    return 1;
  }
}

void emitNop(MachineInstr *MI, int count){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB;
  while(count>0){
    MIB = BuildMI(*MBB, MI, DL, TII.get(X86::NOOP));
    count--;
  }
}

void emitNopAfter(MachineInstr *MI, int count){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB;
  MachineBasicBlock::iterator MBBI = MI;
  while(count>0){
    MIB = BuildMI(*MBB, MI, DL, TII.get(X86::NOOP));
    count--;
    // Move it after MI.
    MBB->remove(MIB);
    MBB->insertAfter(MBBI, MIB);	
  }
}


MachineInstrBuilder pushReg(MachineInstr *MI, unsigned int Reg, unsigned int flags){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::PUSH64r))
    .addReg(Reg, RegState::Kill | flags);
  GFreeDEBUG(1, "> " << *MIB); 	    
  return MIB;
}
 
MachineInstrBuilder popReg(MachineInstr *MI, unsigned int Reg, unsigned int flags){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::POP64r))
    .addReg(Reg, RegState::Define | flags);
  GFreeDEBUG(1, "> " << *MIB); 	    
  return MIB;
}

void pushEFLAGS(MachineInstr *MI){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::PUSHF64));
  GFreeDEBUG(0, "> " << *MIB); 	    
}

void popEFLAGS(MachineInstr *MI){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::POPF64));
  GFreeDEBUG(0, "> " << *MIB); 	    
}


// PUSHF64 %RSP<imp-def>, %RSP<imp-use>, %EFLAGS<imp-use>
// TODO: http://reviews.llvm.org/D6629
void pushEFLAGSinline(MachineInstr *MI, unsigned int saveRegEFLAGS){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 
  // Fix this.
  // 1#
  // Theoretically the code commented below should work but it's not.
  // MBB->addLiveIn(X86::EFLAGS);
  // MBB->addLiveIn(X86::RSP);
  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::PUSHF64));
  // MIB->getOperand(2).setIsUndef();
  // MBB->sortUniqueLiveIns();

  // 2#
  // if ( MachineBasicBlock::LQR_Dead ==
  //      MBB->computeRegisterLiveness((MF->getRegInfo().getTargetRegisterInfo()), X86::EFLAGS, MI, 5000)){
  //   MIB = BuildMI(*MBB, MI, DL, TII.get(TargetOpcode::IMPLICIT_DEF), X86::EFLAGS);       
  //   // errs() << "> " << *MIB;
  // }

  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::INLINEASM))
  //   .addExternalSymbol("pushfq")
  //   .addImm(0)
  //   .addReg(X86::RSP, RegState::ImplicitDefine)
  //   .addReg(X86::RSP, RegState::ImplicitKill)
  //   .addReg(X86::EFLAGS, RegState::ImplicitKill);

  // 3#
  // MIB = BuildMI(*MBB, MI, DL, TII.get(TargetOpcode::COPY)).addReg(X86::RAX, RegState::Define).addReg(X86::EFLAGS);
  // MBB->addLiveIn(X86::EFLAGS);
  // MBB->addLiveIn(X86::RSP);
  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::PUSHF64));
  // MIB->getOperand(2).setIsUndef();
  // MBB->sortUniqueLiveIns();

  // 4#
  if ( MachineBasicBlock::LQR_Dead ==
       MBB->computeRegisterLiveness((MF->getRegInfo().getTargetRegisterInfo()), X86::EFLAGS, MI, 5000)){
    MIB = BuildMI(*MBB, MI, DL, TII.get(TargetOpcode::IMPLICIT_DEF), X86::EFLAGS);       
  }

  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::INLINEASM))
    .addExternalSymbol("pushfq")
    .addImm(0)
    .addReg(X86::RSP, RegState::ImplicitDefine)
    .addReg(X86::RSP, RegState::ImplicitKill)
    .addReg(X86::EFLAGS, RegState::ImplicitKill);

  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::POP64r))
    .addReg(saveRegEFLAGS, RegState::Define);

  MBB->addLiveIn(X86::R12);
  MBB->sortUniqueLiveIns();

  GFreeDEBUG(0, "> " << *MIB); 	    
}



void popEFLAGSinline(MachineInstr *MI, unsigned int saveRegEFLAGS){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB; 

  // 3#
  // MIB = BuildMI(*MBB, MI, DL, TII.get(TargetOpcode::COPY)).addReg(X86::EFLAGS, RegState::Define).addReg(X86::RAX, RegState::Undef);
  // 2#
  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::POPF64));

  // 1#
  // MIB = BuildMI(*MBB, MI, DL, TII.get(X86::INLINEASM))
  //   .addExternalSymbol("popfq")
  //   .addImm(0)
  //   .addReg(X86::RSP, RegState::ImplicitDefine)
  //   .addReg(X86::RSP, RegState::ImplicitKill)
  //   .addReg(X86::EFLAGS, RegState::ImplicitDefine);

  // 4#
  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::PUSH64r))
    .addReg(saveRegEFLAGS);

  MIB = BuildMI(*MBB, MI, DL, TII.get(X86::INLINEASM))
    .addExternalSymbol("popfq")
    .addImm(0)
    .addReg(X86::RSP, RegState::ImplicitDefine)
    .addReg(X86::RSP, RegState::ImplicitKill)
    .addReg(X86::EFLAGS, RegState::ImplicitDefine);

  

  GFreeDEBUG(0, "> " << *MIB); 	    
}

bool needToSaveEFLAGS(MachineInstr *MI){
  MachineBasicBlock *MBB =  MI->getParent();
  MachineBasicBlock::iterator MBBI, MBBIE;
  MBBI = MI;
  MBBIE = MBB->end();
  MachineInstr *CurrentMI;
  unsigned int i;
  // errs() << "TMP DUMPL " << *MBB;
  bool use, def;
  use = false;
  def = false;

  for (; ; MBBI++) {
    
    // If we are at the end of the MBB, follow the successor if and only if there is 
    // one successor.
    while(MBBI == MBBIE && MBB->succ_size() == 1){
      MBB = *MBB->succ_begin();
      MBBI =  MBB->begin();
      MBBIE = MBB->end(); 
    }

    if(MBBI == MBBIE && MBB->succ_size() != 1){ // If there are > 1 successors, stop searching.
      // errs() << "Found anything1!\n";
      return 1;
    }

    CurrentMI = MBBI;
    // errs() << "\t[NS]: " << *CurrentMI;

    if( CurrentMI->isReturn() || CurrentMI->isCall() ){ // We do not preserve eflags across return. It should be safe.
      // errs() << " Found ret!\n";
      return 0;      
    }

    for(i=0; i<CurrentMI->getNumOperands(); i++){
      MachineOperand MO = CurrentMI->getOperand(i);
      if(!MO.isReg() || (MO.getReg() != X86::EFLAGS))
	continue;
      if(MO.isUse()){
	// errs() << " Found use!\n";
	use = 1;
      }
      if(MO.isDef()){
	// errs() << " Found def!\n";
	def = 1;
      }
    }

    if(use == 1) return 1;
    if(def == 1) return 0;
  }
  
  // errs() << "Found anything!\n";
  return 1;
}

bool containsRet(std::vector<unsigned char> MIbytes){
  MIbytes.push_back(0); // This trick is just to not overcomplicate the loop.
  for(unsigned int i = 0; i != MIbytes.size() - 1; i++) {

    if(  MIbytes[i] == 0xc2 || MIbytes[i] == 0xc3 ||
         MIbytes[i] == 0xca || MIbytes[i] == 0xcb ||
       ( MIbytes[i] == 0xff && FFblacklist(MIbytes[i+1]) )){
      return true;
    }
  }
  return false;
}

const TargetRegisterClass *getRegClassFromSize(int size){
  if( size == 1 ){
    return &X86::GR8RegClass;
  }
  if( size == 2 ){
    return &X86::GR16RegClass;
  }
  if( size == 4 ){
    return &X86::GR32RegClass;
  }
  if( size == 8 ){
    return &X86::GR64RegClass;
  }
  assert(false && "[getRegClassFromSize] We should never get here!");
  return 0;
}

void dumpSuccessors(MachineBasicBlock *fromMBB){
  errs() << "Successors of MBB#" << fromMBB->getNumber() << ": ";
  for(MachineBasicBlock::succ_iterator si = fromMBB->succ_begin(), se=fromMBB->succ_end(); se!=si; si++){
    errs() << "MBB#" << (*si)->getNumber() << " ";
  }
  errs()<< "\n";
}


