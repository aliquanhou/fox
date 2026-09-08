use fox_arch::Architecture;
use fox_disasm::create_disassembler;

fn main() {
    let code = [0xEB, 0x03, 0x90, 0x90, 0xC3];
    let disasm = create_disassembler(Architecture::X64).unwrap();
    let insts = disasm.disassemble(&code, 0x1000).unwrap();
    for inst in &insts {
        println!("addr=0x{:X} len={} mnemonic={} operands={} is_jump={} is_cond={} jump_target={:?}",
            inst.address, inst.length, inst.mnemonic, inst.operands,
            inst.is_jump, inst.is_conditional_jump, inst.jump_target);
    }
}
