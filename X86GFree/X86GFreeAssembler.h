#include "X86.h"
#include "llvm/MC/MCStreamer.h"
#include "X86AsmPrinter.h"
#include "X86MCInstLower.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/VirtRegMap.h"
#include "X86GFreeUtils.h"
namespace llvm {
  class LLVM_LIBRARY_VISIBILITY GFreeAssembler{
  public:
    std::unique_ptr<MCCodeEmitter> CodeEmitter;
    MCStreamer *S;
    X86AsmPrinter *Printer;
    X86MCInstLower *MCInstLower;
    const MCSubtargetInfo *STI;
    const TargetRegisterInfo *TRI;
    const TargetInstrInfo *TII;
    MachineBasicBlock *tmpMBB;
    VirtRegMap *VRM;

    void temporaryRewriteRegister(MachineInstr *MI);
    std::vector<unsigned char> lowerEncodeInstr(MachineInstr *RegRewMI);
    bool expandPseudo(MachineInstr *MI);
    bool LowerSubregToReg(MachineInstr *MI);
    bool LowerCopy(MachineInstr *MI);

    GFreeAssembler(MachineFunction &MF, VirtRegMap *VRMap=nullptr);
    std::vector<unsigned char> MachineInstrToBytes(MachineInstr *MI);
    ~GFreeAssembler();
  };

}
