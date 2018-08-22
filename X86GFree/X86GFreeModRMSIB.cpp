#include "X86GFreeAssembler.h"
#include "X86GFreeUtils.h"
#include "X86.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/AllocationOrder.h"
#include "llvm/CodeGen/RegisterClassInfo.h"
#include "llvm/CodeGen/LiveRegMatrix.h"
#include "llvm/CodeGen/LiveInterval.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "./llvm/CodeGen/LiveIntervalAnalysis.h"
#include <set>
#include <list>

using namespace llvm;

#define DEBUG_TYPE "gfreemodrmsib"
STATISTIC(EvilSib , "Number of modified instruction because of an evil ModRM/SIB");

namespace {

  class GFreeModRMSIB : public MachineFunctionPass {
    
  public:
    static char ID;
    VirtRegMap *VRM;
    std::set<unsigned int> VirtRegAlreadyReallocated;
    const TargetRegisterInfo *TRI;
    RegisterClassInfo RegClassInfo;
    LiveRegMatrix *Matrix;
    LiveIntervals *LIS;
    GFreeAssembler *Assembler;

    GFreeModRMSIB() : MachineFunctionPass(ID) {}
    bool runOnMachineBasicBlock(MachineBasicBlock &MBB);
    bool runOnMachineFunction(MachineFunction &MF){
      MachineFunction::iterator MBB, MBBE;
      int loop_counter = 0;
      bool loop_again;
      do{
	loop_again = false;
	for (MBB = MF.begin(), MBBE = MF.end(); MBB != MBBE; ++MBB){
	  loop_again |= runOnMachineBasicBlock(*MBB);
	}
	loop_counter += 1;
      }while(loop_again);

      GFreeDEBUG(2, "[MRM][-] On " << MF.getName() << " we did " << loop_counter << " loops\n");
      return true;
    }
    
    const char *getPassName() const override { return "GFree Mod R/M and SIB bytes handler"; }

    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.setPreservesAll();
      AU.addRequired<VirtRegMap>();
      AU.addRequired<LiveRegMatrix>();
      AU.addPreserved<LiveRegMatrix>();
      AU.addRequired<LiveIntervals>();
      AU.addPreserved<LiveIntervals>();
      MachineFunctionPass::getAnalysisUsage(AU);
    }

    std::vector<unsigned char> AssembleMInewMapping(MachineInstr *MI, unsigned int VirtReg, unsigned int PhysReg);
    int allocateNewRegister(MachineInstr *MI);
    unsigned int doCodeTransformation(MachineInstr *MI);
    unsigned int getSafeReg(MachineInstr *MI, unsigned int PrevPhysReg);
    unsigned int getSafeRegEXT(MachineInstr *MI, unsigned int PrevPhysReg);
    bool MIusesRegister(MachineInstr *MI, unsigned int safeRegister);
    void dumpAllocationOrder(AllocationOrder Order);
  };
  char GFreeModRMSIB::ID = 0;
}


FunctionPass *llvm::createGFreeModRMSIB() {
  return new GFreeModRMSIB();
}

bool neverEncodesRetModRmSib(MachineInstr *MI){
  if(MI->isReturn() || MI->isCall() || MI->isIndirectBranch()){  // We already handle rets/call...
    return true;
  }

  // All the operands must be register or immediates.
  for(MachineOperand &MO: MI->operands()){
    if(! (MO.isReg() || MO.isImm()) ){ 
      return true;
    }
  }
  return false;
}

  
void GFreeModRMSIB::dumpAllocationOrder(AllocationOrder Order){
  unsigned int PhysReg;
  errs() << "ORDER: [";
  while( ( PhysReg=Order.next() ) != 0){
    errs()<< " " << TRI->getName(PhysReg) << " ";
  }
  errs() << "]\n";
  Order.rewind();
}

// The algorithm works as follow:
// - For each "evil" instruction we query the Matrix to check if there is a new
//   physical register that doesn't interfere and such that the instruction becomes safe.
// - If no register is found, then we do some code transformation to make the instruction safe.

// [NOTE] reallocating an already reallocated virtual register is dangerous.
// Take this example:
// <vreg89> = INC64r <vreg89> with vreg89 <--> %RBX, encodes a ret in the modr/m byte.
// So we change the mapping and allocate, i.e, %RDX. The instruction becomes safe.
// Then we run into in:
// <vreg90> = ADD64rr <vreg90>, <vreg89>
// For <vreg90> we can't find a new mapping, but for <vreg89> we found that %RCX suitable.
// But assiging <vreg89> to RCX, makes again the INC64r evil!
// We fix this by keeping the a set of already allocated virtual register (that in this case would contain vreg89) 
// and denying any further change to that register.

// Another corner case is when we have two instructions, let's say A and B, and
// A becomes evil when we realloc a register in B.
// We fix this by doing two loops on the function. 

// During the second loop, A will be evil and so a new register (hopefully)
// will be allocated and the corresponding virtual register will be added to
// the set of already allocated register. So, while processing B (or any other
// instruction after A) that virtual register will not be reallocated.

// When we do a code transformation, we do not change any mapping since it's
// just a sort of wrapper around a MI.

int GFreeModRMSIB::allocateNewRegister(MachineInstr *MI) {
  unsigned int VirtIndex;
  unsigned int VirtReg;
  unsigned int PrevPhysReg;
  unsigned int PhysReg;

  // This list contains for each virtual register how many times the MI is
  // evil after encoding it with a new physical register.
  std::list<int> stillcontainsList;
  // Let's find a virtual register.
  for(VirtIndex=0; VirtIndex < MI->getNumOperands(); VirtIndex++ ){
    MachineOperand &MO = MI->getOperand(VirtIndex);
    if(MO.isReg() && TRI->isVirtualRegister(MO.getReg())){
      stillcontainsList.push_front(1);
      VirtReg = MI->getOperand(VirtIndex).getReg();
      assert(VRM->hasPhys(VirtReg) && "VRM doesn't have this mapping.");

      if (VirtRegAlreadyReallocated.count(VirtReg) != 0){ // Read NOTE above.
	continue;
      }

      LiveInterval &VirtRegInterval = LIS->getInterval(VirtReg);
      PrevPhysReg = VRM->getPhys(VirtReg);

      GFreeDEBUG(1,"[MRM][+] Searching a new register for: " << MI->getOperand(VirtIndex) << ".\n");
      
      AllocationOrder Order(VirtReg, *VRM, RegClassInfo,Matrix);
      // Loop through all the physical registers associable to this virt reg.
      while ((PhysReg = Order.next())) {
	if (PhysReg == PrevPhysReg)
	  continue;
	

	// It's impossible that an istruction contains an evil byte for 4+
	// different registers.
	if(stillcontainsList.front() > 4){
	  GFreeDEBUG(2, "Realloc this register will not solve, stop here.\n");
	  break;
	}

	// Try if with this register, the instruction still encode a ret.
	if(containsRet(AssembleMInewMapping(MI, VirtReg, PhysReg))){ 
	  GFreeDEBUG(3, "  [-] " << TRI->getName(PhysReg) << " : still ret\n");
	  stillcontainsList.front()++;
	  continue;
	}

	// If no interference, then we found a free register.	
	if ((Matrix->checkInterference(VirtRegInterval, PhysReg) == LiveRegMatrix::IK_Free)){ 
	  ++EvilSib;
	  VRM->clearVirt(VirtReg);
	  Matrix->assign(VirtRegInterval, PhysReg);
	  
	  GFreeDEBUG(1,"[MRM][+] found: " << TRI->getName(PhysReg) <<
	               " from " << TRI->getName(PrevPhysReg) << " ("   <<
		       MI->getOperand(VirtIndex)  <<  ") \n");
	  VirtRegAlreadyReallocated.insert(VirtReg); 
	  Matrix->invalidateVirtRegs();
	  return 1;
	}
	GFreeDEBUG(3,"  [-] " << TRI->getName(PhysReg) << " : interference\n");
      }
    }  
  }


  // This means: if all the virtual registers had exceeded the limit of 3
  // reallocation (and in every reallocation the encoding still contains a
  // ret), than we can't do nothing in this pass.  An example are instructions
  // that encode a ret in a immediate.  We return -1 and inform the main to not
  // further process this MI thourgh a code transformation, because it would be
  // useless.  [5,5] [3,2,5]

  if(*std::min_element(stillcontainsList.begin(), stillcontainsList.end()) >= 4){
    GFreeDEBUG(1,"[MRM][-] Do nothing.\n");
    return -1;
  }

  // Otherwise, it means that at least one register didn't execeded the limit,
  // so we can do a code transformation.
  else{
    GFreeDEBUG(0,"[MRM][-] Do codetransform.\n");
    return 0;
  }
}


std::vector<unsigned char> GFreeModRMSIB::AssembleMInewMapping(MachineInstr *MI, 
							       unsigned int VirtReg, 
							       unsigned int PhysReg){
  assert(VRM->hasPhys(VirtReg) && "VRM doesn't have this mapping.");
  unsigned int PrevPhysReg = VRM->getPhys(VirtReg);

  // Temporary create the new virt<->phys mapping
  VRM->clearVirt(VirtReg);
  VRM->assignVirt2Phys(VirtReg, PhysReg);

  std::vector<unsigned char> MIBytes = Assembler->MachineInstrToBytes(MI);

  // Restore the old mapping.
  VRM->clearVirt(VirtReg);
  VRM->assignVirt2Phys(VirtReg, PrevPhysReg);
  return MIBytes;
}

bool GFreeModRMSIB::MIusesRegister(MachineInstr *MI, unsigned int safeRegister){
  unsigned int PhysReg;
  for(const MachineOperand &MO : MI->operands()){
    if( !MO.isReg() )
      continue;
    
    // If necessary, translate virtual register.
    PhysReg = TRI->isVirtualRegister(MO.getReg()) ? VRM->getPhys(MO.getReg()) : MO.getReg();

    if(PhysReg == llvm::getX86SubSuperRegister(safeRegister, 64, false) ||
       PhysReg == llvm::getX86SubSuperRegister(safeRegister, 32, false) ||
       PhysReg == llvm::getX86SubSuperRegister(safeRegister, 16, false) ||
       PhysReg == llvm::getX86SubSuperRegister(safeRegister, 8,  true ) ||
       PhysReg == llvm::getX86SubSuperRegister(safeRegister, 8,  false) )

      return true;
  }

  return false;
  
}

// We can't use R13 straight. Had problem with this instruction,
// where %r13d was already there and we replaced (failing!) rbx with r13 in the mov.
// mov  %r13d,0x48(%r13,%rax,8)
//      ^
//      |
// push %r13
// mov  %rbx,%r13
// mov  %r13d,0x48(%r13,%rax,8)
// mov  %r13,%rbx
// pop  %r13

unsigned int GFreeModRMSIB::getSafeReg(MachineInstr *MI, unsigned int PrevVirtReg){
  MachineFunction *MF = MI->getParent()->getParent();
  unsigned int safeRegisters[3] =  {X86::R13, X86::R15, X86::R14};
  int i;

  // If MI *doesn't* use safeRegister[i] (or any of his subregisters),
  // then we can use it.
  for(i=0; i<3; i++){
    if(! MIusesRegister(MI, safeRegisters[i]) )
      break;
  }
  
  // This should never happen because an instruction can use up to 3
  // register, but if we are here one of those 3 register must be different for
  // one contained in usableRegisters, otherwise the MI wasn't evil.
  assert(i!=3 && "Can't find a safe reg in X86GFreeModRMSIB.cpp!");

  
  // We return the right size of the safe reg (es: R13d, R13w)
  const TargetRegisterClass *VirtRegRC = MF->getRegInfo().getRegClass(PrevVirtReg);
  // TODO: support X86::GR32_ABCDRegClass
  if(VirtRegRC == &X86::GR32_ABCDRegClass) return 0;
  const TargetRegisterClass *LargestVirtRegRC = TRI->getLargestLegalSuperClass(VirtRegRC,*MF); // GR64_with_sub_8bit -> GR64
  // errs() << "MI: " << *MI;
  // errs() << "Name: " << TRI->getRegClassName(VirtRegRC) << "\n";
  // errs() << "NameLARGE: " << TRI->getRegClassName(TRI->getLargestLegalSuperClass(VirtRegRC,*MF)) << "\n";
  if( LargestVirtRegRC == &X86::GR8RegClass){
    return llvm::getX86SubSuperRegister(safeRegisters[i], 8,  false);
  }
  else if ( LargestVirtRegRC == &X86::GR16RegClass){
    return llvm::getX86SubSuperRegister(safeRegisters[i], 16,  false);
  }
  else if( LargestVirtRegRC == &X86::GR32RegClass){
    return llvm::getX86SubSuperRegister(safeRegisters[i], 32,  false);
  }
  else if ( LargestVirtRegRC == &X86::GR64RegClass){
    return llvm::getX86SubSuperRegister(safeRegisters[i], 64,  false);
  }
  return 0;
}

unsigned int getMOVrrOpcode(unsigned int PrevPhysReg){
  if( X86::GR8RegClass.contains(PrevPhysReg)){
    return X86::MOV8rr;
  }
  else if (X86::GR16RegClass.contains(PrevPhysReg)){
    return X86::MOV16rr;
  }
  else if( X86::GR32RegClass.contains(PrevPhysReg)){
    return X86::MOV32rr;
  }
  else if (X86::GR64RegClass.contains(PrevPhysReg)){
    return X86::MOV64rr;
  }
  else {
    return 0;
  }
}

// Returns true if a code transformation is done, false otherwise.
unsigned int GFreeModRMSIB::doCodeTransformation(MachineInstr *MI) {

  MachineBasicBlock *MBB =  MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86Subtarget &STI = MF->getSubtarget<X86Subtarget>();
  const X86InstrInfo &TII = *STI.getInstrInfo();
  DebugLoc DL = MI->getDebugLoc();
  MachineInstrBuilder MIB;

  unsigned int VirtIndex;
  unsigned int VirtReg;
  unsigned int PrevPhysReg;
  unsigned int NewReg;
  unsigned int MovOpcode;
  // Count how many instruction are inserted before and after the
  // target instruction.
  unsigned int InsertedBefore = 0;
  unsigned int InsertedAfter = 0;
  // Here we loop thorugh all the virtual register of MI. We choose a suitable
  // NewReg (R13,R14..), and check that the MI, with the new mapping, doesn't
  // contains an evil sib/modrm anymore.
  for(VirtIndex=0; VirtIndex < MI->getNumOperands(); VirtIndex++ ){
    MachineOperand &MO = MI->getOperand(VirtIndex);
    // errs() << *VRM;
    if(MO.isReg() && TRI->isVirtualRegister(MO.getReg())){
        VirtReg = MI->getOperand(VirtIndex).getReg();
	PrevPhysReg = VRM->getPhys(VirtReg);
	NewReg = getSafeReg(MI, VirtReg);
	MovOpcode = getMOVrrOpcode(PrevPhysReg);
	if(NewReg == 0 || MovOpcode == 0){
	  errs() << "[TODO] MI not handled (1): " << *MI;
	  return 0;
	}
	if(!containsRet(AssembleMInewMapping(MI, VirtReg, NewReg)))
	  break;
    }
  }
  
  // We exited from the loop because the operands were finished.
  if(VirtIndex == MI->getNumOperands()){
    errs() << "[TODO] MI not handled (2): " << *MI;
    return 0;
  }
  // Otherwise do the code transformation.
  ++EvilSib; // Update stats.
  unsigned int SuperRegSafe = llvm::getX86SubSuperRegister(NewReg, 64,  false);
  MBB->addLiveIn(SuperRegSafe);
  MBB->sortUniqueLiveIns();

  
  // PUSH R13;
  pushReg(MI, SuperRegSafe, RegState::Undef); 
  InsertedBefore++;
  // If this is a copy and we are targeting the first register, we can skip this mov
  if(! ((MI->getOpcode() == TargetOpcode::COPY) &&
	(VirtIndex == 0)) )
    {
      // MOV VirtReg -> R13
      MIB = BuildMI(*MBB, MI, DL, TII.get(MovOpcode))
	.addReg(NewReg, RegState::Define)
	.addReg(VirtReg, RegState::Undef);
      GFreeDEBUG(1, "> " << *MIB);
      InsertedBefore++;
    }
  
  // INST with R13*
  GFreeDEBUG(1, "< " << *MI); 	    

  // Here we replace the "evil" reg with the new safe ref.
  MI->substituteRegister(VirtReg, NewReg, 0, *TRI); 
  
  // But we also have to replace every virtual register that is allocated on
  // the same physical register as the "evil" reg.
  // This was a bug found
  // lea    0x0(%r10,%rcx,8),%r10
  // was wrongly translated in:
  // mov    %r10,%r13
  // lea    0x0(%r13,%rcx,8),%r10
  // mov    %r13,%r10 
  // now is translated in:
  // mov    %r10,%r13
  // lea    0x0(%r13,%rcx,8),%r13
  // mov    %r13,%r10
  
  for(VirtIndex=0; VirtIndex < MI->getNumOperands(); VirtIndex++ ){
    MachineOperand &MO = MI->getOperand(VirtIndex);
    if(MO.isReg() && TRI->isVirtualRegister(MO.getReg()) && 
       VRM->getPhys(VirtReg) == VRM->getPhys(MO.getReg())){
      MIB = BuildMI(*MBB, MI, DL, TII.get(TargetOpcode::IMPLICIT_DEF), MO.getReg());
      MO.setReg(NewReg);
    }
  }

  VirtRegAlreadyReallocated.insert(VirtReg); 
  GFreeDEBUG(1, "> " << *MI); 	    

  MachineInstrBuilder MovMIB;
  // If this is a copy and we are targeting the second register, we
  // can skip this mov
  if(! ((MI->getOpcode() == TargetOpcode::COPY) &&
	(VirtIndex == 1)) )
    {
      // MOV R13 -> VirtReg
      MovMIB = BuildMI(*MBB, MI, DL, TII.get(MovOpcode)) 
	.addReg(VirtReg, RegState::Define)
	.addReg(NewReg, RegState::Undef);
      GFreeDEBUG(1, "> " << *MovMIB);
      InsertedAfter++;
    }


  // POP R13;
  MachineInstrBuilder PopMIB = popReg(MI, SuperRegSafe); 
  InsertedAfter++;
  
  // Move MI in the middle, before the last mov (MovMIB) if it was
  // created, otherwise before the pop (PopMIB)
  MBB->remove(MI);
  MBB->insert(MovMIB ? MovMIB : PopMIB,MI); 

  // Fix up the live intervals. 
  ArrayRef<unsigned> Arr(VirtReg);
  MachineBasicBlock::iterator MBBI = MI;
  LIS->RemoveMachineInstrFromMaps(MI);
  LIS->InsertMachineInstrRangeInMaps(std::prev(MBBI,InsertedBefore), std::next(MBBI,InsertedAfter+1));
  LIS->repairIntervalsInRange(MBB, MBBI, MBBI, Arr);

  return 1;
}


bool GFreeModRMSIB::runOnMachineBasicBlock(MachineBasicBlock &MBB) {
  MachineFunction *MF = MBB.getParent();
  VRM = &getAnalysis<VirtRegMap>();
  Matrix = &getAnalysis<LiveRegMatrix>();
  LIS = &getAnalysis<LiveIntervals>();
  TRI = MF->getSubtarget().getRegisterInfo();
  RegClassInfo.runOnMachineFunction(VRM->getMachineFunction());
  MachineBasicBlock::iterator MBBI, MBBIE;
  MachineInstr *MI;
  Assembler = new GFreeAssembler(*MF, VRM);

  bool loop_again = false;
  // VirtRegAlreadyReallocated.clear();
  for (MBBI = MBB.begin(), MBBIE = MBB.end(); MBBI != MBBIE; MBBI++) {
    
    MI = MBBI;
    if( neverEncodesRetModRmSib(MI) ) 
      continue;
    // 1. 2. 3. 4.
    std::vector<unsigned char> MIbytes = Assembler->MachineInstrToBytes(MI);
    
    // 5. Check if there's a ret.
    if( containsRet(MIbytes) ){
      GFreeDEBUG(1, "[MRM][+] Contains Ret: " << *MI); 
      
      int result = allocateNewRegister(MI);

      if (result == 1){  // We did something (a new register was found).
	loop_again = true;
	continue;
      }
      if( result == -1 ){ // We can't do nothing.
	continue;
      }
      if( result ==  0 ){ // We can do something.
	loop_again |= doCodeTransformation(MI);
      }
    }
  } // end while 

  delete Assembler;	
  // errs()<< "After MODRM/SIB: " << MBB;
  return loop_again;
}

static RegisterPass<GFreeModRMSIB> X("gfreemodrmsib", "GFreeModRMSIB");


