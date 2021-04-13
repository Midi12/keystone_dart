import 'asm_builder_base.dart';
import 'instruction.dart';
import 'operand.dart';

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

class ImmediateValueOperandIntel extends ImmediateValueOperand {
  const ImmediateValueOperandIntel(int value) : super(value);
}

// class MemoryValueOperandIntel extends MemoryValueOperand {
//   const MemoryValueOperandIntel(dynamic item) : super(item);

//   @override
//   String format() => '$value';
// }

class DereferencedOperandIntel extends DereferencedOperand {
  const DereferencedOperandIntel(Operand item) : super(item);

  @override
  String format() => '[${value.format()}]';
}

class LabelOperandIntel extends LabelOperand {
  const LabelOperandIntel(value) : super(value);
}

class ZeroOperandInstructionIntel extends Instruction {
  const ZeroOperandInstructionIntel(String name) : super(name);

  @override
  String format() => '$name';
}

class OneOperandInstructionIntel extends Instruction {
  final Operand _op1;

  const OneOperandInstructionIntel(String name, this._op1) : super(name);

  @override
  String format() => '$name ${_op1.format()}';
}

class TwoOperandsInstructionIntel extends Instruction {
  final Operand _op1;
  final Operand _op2;

  const TwoOperandsInstructionIntel(String name, this._op1, this._op2) : super(name);

  @override
  String format() => '$name ${_op1.format()}, ${_op2.format()}';
}

class AsmBuilderIntel extends AsmBuilderBase {

  ImmediateValueOperand imm(int value) => ImmediateValueOperandIntel(value);
  // MemoryValueOperand mem(dynamic item) => MemoryValueOperandIntel(item);
  DereferencedOperand deref(Operand item) => DereferencedOperandIntel(item);
  LabelOperand lab(String name) => LabelOperandIntel(name);

  AsmBuilderBase label(LabelOperand name) {
    appendRaw('${name.format()}:');
    return this;
  }

  AsmBuilderBase mov(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('mov', dest, src));
    return this;
  }

  AsmBuilderBase pop(Operand reg) {
    append(OneOperandInstructionIntel('pop', reg));
    return this;
  }

  AsmBuilderBase push(Operand item) {
    append(OneOperandInstructionIntel('push', item));
    return this;
  }

  AsmBuilderBase add(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('add', dest, src));
    return this;
  }

  AsmBuilderBase and(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('and', dest, src));
    return this;
  }

  AsmBuilderBase call(Operand label) {
    append(OneOperandInstructionIntel('call', label));
    return this;
  }

  AsmBuilderBase cmp(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('cmp', op1, op2));
    return this;
  }

  AsmBuilderBase dec(Operand dest) {
    append(OneOperandInstructionIntel('dec', dest));
    return this;
  }

  AsmBuilderBase div(Operand reg) {
    append(OneOperandInstructionIntel('div', reg));
    return this;
  }

  AsmBuilderBase inc(Operand dest) {
    append(OneOperandInstructionIntel('inc', dest));
    return this;
  }

  AsmBuilderBase je(Operand label) {
    append(OneOperandInstructionIntel('je', label));
    return this;
  }

  AsmBuilderBase jg(Operand label) {
    append(OneOperandInstructionIntel('jg', label));
    return this;
  }

  AsmBuilderBase jge(Operand label) {
    append(OneOperandInstructionIntel('jge', label));
    return this;
  }

  AsmBuilderBase jl(Operand label) {
    append(OneOperandInstructionIntel('jl', label));
    return this;
  }

  AsmBuilderBase jle(Operand label) {
    append(OneOperandInstructionIntel('jle', label));
    return this;
  }

  AsmBuilderBase jmp(Operand label) {
    append(OneOperandInstructionIntel('jmp', label));
    return this;
  }

  AsmBuilderBase jne(Operand label) {
    append(OneOperandInstructionIntel('jne', label));
    return this;
  }

  AsmBuilderBase jnz(Operand label) {
    append(OneOperandInstructionIntel('jnz', label));
    return this;
  }

  AsmBuilderBase jz(Operand label) {
    append(OneOperandInstructionIntel('jz', label));
    return this;
  }

  AsmBuilderBase mul(Operand reg) {
    append(OneOperandInstructionIntel('mul', reg));
    return this;
  }

  AsmBuilderBase nop() {
    append(ZeroOperandInstructionIntel('nop'));
    return this;
  }

  AsmBuilderBase or(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('or', dest, src));
    return this;
  }

  AsmBuilderBase ret() {
    append(ZeroOperandInstructionIntel('ret'));
    return this;
  }

  AsmBuilderBase shl(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shl', dest, count));
    return this;
  }

  AsmBuilderBase shr(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shr', dest, count));
    return this;
  }

  AsmBuilderBase sub(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('sub', dest, src));
    return this;
  }

  AsmBuilderBase test(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('test', op1, op2));
    return this;
  }

  AsmBuilderBase xor(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('xor', dest, src));
    return this;
  }
}

class AsmBuilderIntel16 extends AsmBuilderIntel {
  RegisterOperand get ax => _ax;
  RegisterOperand get bx => _bx;
  RegisterOperand get cx => _cx;
  RegisterOperand get dx => _dx;
  RegisterOperand get bp => _bp;
  RegisterOperand get sp => _sp;
  RegisterOperand get si => _si;
  RegisterOperand get di => _di;
  RegisterOperand get ip => _ip;

  RegisterOperand get ah => _ah;
  RegisterOperand get bh => _bh;
  RegisterOperand get ch => _ch;
  RegisterOperand get dh => _dh;

  RegisterOperand get al => _al;
  RegisterOperand get bl => _bl;
  RegisterOperand get cl => _cl;
  RegisterOperand get dl => _dl;
}

class AsmBuilderIntel32 extends AsmBuilderIntel16 {
  RegisterOperand get eax => _eax;
  RegisterOperand get ebx => _ebx;
  RegisterOperand get ecx => _ecx;
  RegisterOperand get edx => _edx;
  RegisterOperand get ebp => _ebp;
  RegisterOperand get esp => _esp;
  RegisterOperand get esi => _esi;
  RegisterOperand get edi => _edi;
  RegisterOperand get eip => _eip;

  AsmBuilderBase pusha() {
    append(ZeroOperandInstructionIntel('pusha'));
    return this;
  }

  AsmBuilderBase popa() {
    append(ZeroOperandInstructionIntel('pusha'));
    return this;
  }

  AsmBuilderBase pushf() {
    append(ZeroOperandInstructionIntel('pushf'));
    return this;
  }

  AsmBuilderBase popf() {
    append(ZeroOperandInstructionIntel('pushf'));
    return this;
  }
}

class AsmBuilderIntel64 extends AsmBuilderIntel32 {
  RegisterOperand get rax => _rax;
  RegisterOperand get rbx => _rbx;
  RegisterOperand get rcx => _rcx;
  RegisterOperand get rdx => _rdx;
  RegisterOperand get rbp => _rbp;
  RegisterOperand get rsp => _rsp;
  RegisterOperand get rsi => _rsi;
  RegisterOperand get rdi => _rdi;
  RegisterOperand get r8 => _r8;
  RegisterOperand get r9 => _r9;
  RegisterOperand get r10 => _r10;
  RegisterOperand get r11 => _r11;
  RegisterOperand get r12 => _r12;
  RegisterOperand get r13 => _r13;
  RegisterOperand get r14 => _r14;
  RegisterOperand get r15 => _r15;
  RegisterOperand get rip => _rip;

  @override
  AsmBuilderBase pusha() => throw UnimplementedError();

  @override
  AsmBuilderBase popa() => throw UnimplementedError();
}