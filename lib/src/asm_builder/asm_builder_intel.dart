import 'asm_builder_base.dart';
import 'instruction.dart';
import 'operand.dart';

/// A class representing a register operand in Intel syntax
class RegisterOperandIntel extends RegisterOperand {
  const RegisterOperandIntel(String name) : super(name);
}

const _rax = RegisterOperandIntel('rax');
const _rbx = RegisterOperandIntel('rbx');
const _rcx = RegisterOperandIntel('rcx');
const _rdx = RegisterOperandIntel('rdx');
const _rbp = RegisterOperandIntel('rbp');
const _rsp = RegisterOperandIntel('rsp');
const _rsi = RegisterOperandIntel('rsi');
const _rdi = RegisterOperandIntel('rdi');
const _r8 = RegisterOperandIntel('r8');
const _r9 = RegisterOperandIntel('r9');
const _r10 = RegisterOperandIntel('r10');
const _r11 = RegisterOperandIntel('r11');
const _r12 = RegisterOperandIntel('r12');
const _r13 = RegisterOperandIntel('r13');
const _r14 = RegisterOperandIntel('r14');
const _r15 = RegisterOperandIntel('r15');
const _rip = RegisterOperandIntel('rip');

const _eax = RegisterOperandIntel('eax');
const _ebx = RegisterOperandIntel('ebx');
const _ecx = RegisterOperandIntel('ecx');
const _edx = RegisterOperandIntel('edx');
const _ebp = RegisterOperandIntel('ebp');
const _esp = RegisterOperandIntel('esp');
const _esi = RegisterOperandIntel('esi');
const _edi = RegisterOperandIntel('edi');
const _eip = RegisterOperandIntel('eip');

const _ax = RegisterOperandIntel('ax');
const _bx = RegisterOperandIntel('bx');
const _cx = RegisterOperandIntel('cx');
const _dx = RegisterOperandIntel('dx');
const _bp = RegisterOperandIntel('bp');
const _sp = RegisterOperandIntel('sp');
const _si = RegisterOperandIntel('si');
const _di = RegisterOperandIntel('di');
const _ip = RegisterOperandIntel('ip');

const _ah = RegisterOperandIntel('ah');
const _bh = RegisterOperandIntel('bh');
const _ch = RegisterOperandIntel('ch');
const _dh = RegisterOperandIntel('dh');

const _al = RegisterOperandIntel('al');
const _bl = RegisterOperandIntel('bl');
const _cl = RegisterOperandIntel('cl');
const _dl = RegisterOperandIntel('dl');

/// A class representing an immediate value operand in Intel syntax
class ImmediateValueOperandIntel extends ImmediateValueOperand {
  const ImmediateValueOperandIntel(int value) : super(value);
}

// class MemoryValueOperandIntel extends MemoryValueOperand {
//   const MemoryValueOperandIntel(dynamic item) : super(item);

//   @override
//   String format() => '$value';
// }

/// A class representing a dereferenced operand in Intel syntax
class DereferencedOperandIntel extends DereferencedOperand {
  const DereferencedOperandIntel(Operand item) : super(item);

  @override
  String format() => '[${value.format()}]';
}

/// A class representing a label operand in Intel syntax
class LabelOperandIntel extends LabelOperand {
  const LabelOperandIntel(value) : super(value);
}

/// A class representing an instruction with no operand in Intel syntax
class ZeroOperandInstructionIntel extends Instruction {
  const ZeroOperandInstructionIntel(String name) : super(name);

  @override
  String format() => '$name';
}

/// A class representing an instruction with one operand in Intel syntax
class OneOperandInstructionIntel extends Instruction {
  final Operand _op1;

  const OneOperandInstructionIntel(String name, this._op1) : super(name);

  @override
  String format() => '$name ${_op1.format()}';
}

/// A class representing an instruction with two operands in Intel syntax
class TwoOperandsInstructionIntel extends Instruction {
  final Operand _op1;
  final Operand _op2;

  const TwoOperandsInstructionIntel(String name, this._op1, this._op2)
      : super(name);

  @override
  String format() => '$name ${_op1.format()}, ${_op2.format()}';
}

/// The Intel syntax helper
class AsmBuilderIntel extends AsmBuilderBase {
  /// Creates a `ImmediateValueOperandIntel`
  ImmediateValueOperand imm(int value) => ImmediateValueOperandIntel(value);

  // MemoryValueOperand mem(dynamic item) => MemoryValueOperandIntel(item);

  /// Creates a `DereferencedOperandIntel`
  DereferencedOperand deref(Operand item) => DereferencedOperandIntel(item);

  /// Creates a `LabelOperandIntel`
  LabelOperand lab(String name) => LabelOperandIntel(name);

  /// Appends a `label` instruction to the instruction list
  AsmBuilderBase label(LabelOperand name) {
    appendRaw('${name.format()}:');
    return this;
  }

  /// Appends a `mov` instruction to the instruction list
  AsmBuilderBase mov(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('mov', dest, src));
    return this;
  }

  /// Appends a `pop` instruction to the instruction list
  AsmBuilderBase pop(Operand reg) {
    append(OneOperandInstructionIntel('pop', reg));
    return this;
  }

  /// Appends a `push` instruction to the instruction list
  AsmBuilderBase push(Operand item) {
    append(OneOperandInstructionIntel('push', item));
    return this;
  }

  /// Appends a `add` instruction to the instruction list
  AsmBuilderBase add(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('add', dest, src));
    return this;
  }

  /// Appends a `and` instruction to the instruction list
  AsmBuilderBase and(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('and', dest, src));
    return this;
  }

  /// Appends a `call` instruction to the instruction list
  AsmBuilderBase call(Operand label) {
    append(OneOperandInstructionIntel('call', label));
    return this;
  }

  /// Appends a `cmp` instruction to the instruction list
  AsmBuilderBase cmp(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('cmp', op1, op2));
    return this;
  }

  /// Appends a `dec` instruction to the instruction list
  AsmBuilderBase dec(Operand dest) {
    append(OneOperandInstructionIntel('dec', dest));
    return this;
  }

  /// Appends a `div` instruction to the instruction list
  AsmBuilderBase div(Operand reg) {
    append(OneOperandInstructionIntel('div', reg));
    return this;
  }

  /// Appends a `inc` instruction to the instruction list
  AsmBuilderBase inc(Operand dest) {
    append(OneOperandInstructionIntel('inc', dest));
    return this;
  }

  /// Appends a `je` instruction to the instruction list
  AsmBuilderBase je(Operand label) {
    append(OneOperandInstructionIntel('je', label));
    return this;
  }

  /// Appends a `jg` instruction to the instruction list
  AsmBuilderBase jg(Operand label) {
    append(OneOperandInstructionIntel('jg', label));
    return this;
  }

  /// Appends a `jge` instruction to the instruction list
  AsmBuilderBase jge(Operand label) {
    append(OneOperandInstructionIntel('jge', label));
    return this;
  }

  /// Appends a `jl` instruction to the instruction list
  AsmBuilderBase jl(Operand label) {
    append(OneOperandInstructionIntel('jl', label));
    return this;
  }

  /// Appends a `jle` instruction to the instruction list
  AsmBuilderBase jle(Operand label) {
    append(OneOperandInstructionIntel('jle', label));
    return this;
  }

  /// Appends a `jmp` instruction to the instruction list
  AsmBuilderBase jmp(Operand label) {
    append(OneOperandInstructionIntel('jmp', label));
    return this;
  }

  /// Appends a `jne` instruction to the instruction list
  AsmBuilderBase jne(Operand label) {
    append(OneOperandInstructionIntel('jne', label));
    return this;
  }

  /// Appends a `jnz` instruction to the instruction list
  AsmBuilderBase jnz(Operand label) {
    append(OneOperandInstructionIntel('jnz', label));
    return this;
  }

  /// Appends a `jz` instruction to the instruction list
  AsmBuilderBase jz(Operand label) {
    append(OneOperandInstructionIntel('jz', label));
    return this;
  }

  /// Appends a `mul` instruction to the instruction list
  AsmBuilderBase mul(Operand reg) {
    append(OneOperandInstructionIntel('mul', reg));
    return this;
  }

  /// Appends a `nop` instruction to the instruction list
  AsmBuilderBase nop() {
    append(ZeroOperandInstructionIntel('nop'));
    return this;
  }

  /// Appends a `or` instruction to the instruction list
  AsmBuilderBase or(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('or', dest, src));
    return this;
  }

  /// Appends a `ret` instruction to the instruction list
  AsmBuilderBase ret() {
    append(ZeroOperandInstructionIntel('ret'));
    return this;
  }

  /// Appends a `shl` instruction to the instruction list
  AsmBuilderBase shl(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shl', dest, count));
    return this;
  }

  /// Appends a `shr` instruction to the instruction list
  AsmBuilderBase shr(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shr', dest, count));
    return this;
  }

  /// Appends a `sub` instruction to the instruction list
  AsmBuilderBase sub(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('sub', dest, src));
    return this;
  }

  /// Appends a `test` instruction to the instruction list
  AsmBuilderBase test(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('test', op1, op2));
    return this;
  }

  /// Appends a `xor` instruction to the instruction list
  AsmBuilderBase xor(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('xor', dest, src));
    return this;
  }
}

/// The 16 bit Intel syntax helper
class AsmBuilderIntel16 extends AsmBuilderIntel {
  /// The `ax` register
  RegisterOperand get ax => _ax;

  /// The `bx` register
  RegisterOperand get bx => _bx;

  /// The `cx` register
  RegisterOperand get cx => _cx;

  /// The `dx` register
  RegisterOperand get dx => _dx;

  /// The `bp` register
  RegisterOperand get bp => _bp;

  /// The `sp` register
  RegisterOperand get sp => _sp;

  /// The `si` register
  RegisterOperand get si => _si;

  /// The `di` register
  RegisterOperand get di => _di;

  /// The `ip` register
  RegisterOperand get ip => _ip;

  /// The `ah` register
  RegisterOperand get ah => _ah;

  /// The `bh` register
  RegisterOperand get bh => _bh;

  /// The `ch` register
  RegisterOperand get ch => _ch;

  /// The `dh` register
  RegisterOperand get dh => _dh;

  /// The `al` register
  RegisterOperand get al => _al;

  /// The `bl` register
  RegisterOperand get bl => _bl;

  /// The `cl` register
  RegisterOperand get cl => _cl;

  /// The `dl` register
  RegisterOperand get dl => _dl;
}

/// The 32 bit Intel syntax helper
class AsmBuilderIntel32 extends AsmBuilderIntel16 {
  /// The `eax` register
  RegisterOperand get eax => _eax;

  /// The `ebx` register
  RegisterOperand get ebx => _ebx;

  /// The `ecx` register
  RegisterOperand get ecx => _ecx;

  /// The `edx` register
  RegisterOperand get edx => _edx;

  /// The `ebp` register
  RegisterOperand get ebp => _ebp;

  /// The `esp` register
  RegisterOperand get esp => _esp;

  /// The `esi` register
  RegisterOperand get esi => _esi;

  /// The `edi` register
  RegisterOperand get edi => _edi;

  /// The `eip` register
  RegisterOperand get eip => _eip;

  /// Appends a `pusha` instruction to the instruction list
  AsmBuilderBase pusha() {
    append(ZeroOperandInstructionIntel('pusha'));
    return this;
  }

  /// Appends a `popa` instruction to the instruction list
  AsmBuilderBase popa() {
    append(ZeroOperandInstructionIntel('pusha'));
    return this;
  }

  /// Appends a `pushf` instruction to the instruction list
  AsmBuilderBase pushf() {
    append(ZeroOperandInstructionIntel('pushf'));
    return this;
  }

  /// Appends a `popf` instruction to the instruction list
  AsmBuilderBase popf() {
    append(ZeroOperandInstructionIntel('pushf'));
    return this;
  }
}

class AsmBuilderIntel64 extends AsmBuilderIntel32 {
  /// The `rax` register
  RegisterOperand get rax => _rax;

  /// The `rbx` register
  RegisterOperand get rbx => _rbx;

  /// The `rcx` register
  RegisterOperand get rcx => _rcx;

  /// The `rdx` register
  RegisterOperand get rdx => _rdx;

  /// The `rbp` register
  RegisterOperand get rbp => _rbp;

  /// The `rsp` register
  RegisterOperand get rsp => _rsp;

  /// The `rsi` register
  RegisterOperand get rsi => _rsi;

  /// The `rdi` register
  RegisterOperand get rdi => _rdi;

  /// The `r8` register
  RegisterOperand get r8 => _r8;

  /// The `r9` register
  RegisterOperand get r9 => _r9;

  /// The `r10` register
  RegisterOperand get r10 => _r10;

  /// The `r11` register
  RegisterOperand get r11 => _r11;

  /// The `r12` register
  RegisterOperand get r12 => _r12;

  /// The `r13` register
  RegisterOperand get r13 => _r13;

  /// The `r14` register
  RegisterOperand get r14 => _r14;

  /// The `r15` register
  RegisterOperand get r15 => _r15;

  /// The `rip` register
  RegisterOperand get rip => _rip;

  /// The `pusha` instruction is not allowed in 64 bit
  @override
  AsmBuilderBase pusha() => throw UnimplementedError();

  /// The `popa` instruction is not allowed in 64 bit
  @override
  AsmBuilderBase popa() => throw UnimplementedError();

  /// Appends a `pushfq` instruction to the instruction list
  AsmBuilderBase pushfq() {
    append(ZeroOperandInstructionIntel('pushfq'));
    return this;
  }

  /// Appends a `popfq` instruction to the instruction list
  AsmBuilderBase popfq() {
    append(ZeroOperandInstructionIntel('pushfq'));
    return this;
  }
}
