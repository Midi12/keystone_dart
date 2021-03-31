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

class MemoryValueOperandIntel extends MemoryValueOperand {
  const MemoryValueOperandIntel(dynamic item) : super(item);

  @override
  String format() => '$value';
}

class DereferencedOperandIntel extends DereferencedOperand {
  const DereferencedOperandIntel(Operand item) : super(item);

  @override
  String format() => '[${value.format()}]';
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
  MemoryValueOperand mem(dynamic item) => MemoryValueOperandIntel(item);
  DereferencedOperand deref(Operand item) => DereferencedOperandIntel(item);

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
  RegisterOperand get ax => RegisterOperandIntel('ax');
  RegisterOperand get bx => RegisterOperandIntel('bx');
  RegisterOperand get cx => RegisterOperandIntel('cx');
  RegisterOperand get dx => RegisterOperandIntel('dx');
  RegisterOperand get bp => RegisterOperandIntel('bp');
  RegisterOperand get sp => RegisterOperandIntel('sp');
  RegisterOperand get si => RegisterOperandIntel('si');
  RegisterOperand get di => RegisterOperandIntel('di');
  RegisterOperand get ip => RegisterOperandIntel('ip');

  RegisterOperand get ah => RegisterOperandIntel('ah');
  RegisterOperand get bh => RegisterOperandIntel('bh');
  RegisterOperand get ch => RegisterOperandIntel('ch');
  RegisterOperand get dh => RegisterOperandIntel('dh');

  RegisterOperand get al => RegisterOperandIntel('al');
  RegisterOperand get bl => RegisterOperandIntel('bl');
  RegisterOperand get cl => RegisterOperandIntel('cl');
  RegisterOperand get dl => RegisterOperandIntel('dl');
}

class AsmBuilderIntel32 extends AsmBuilderIntel16 {
  RegisterOperand get eax => RegisterOperandIntel('eax');
  RegisterOperand get ebx => RegisterOperandIntel('ebx');
  RegisterOperand get ecx => RegisterOperandIntel('ecx');
  RegisterOperand get edx => RegisterOperandIntel('edx');
  RegisterOperand get ebp => RegisterOperandIntel('ebp');
  RegisterOperand get esp => RegisterOperandIntel('esp');
  RegisterOperand get esi => RegisterOperandIntel('esi');
  RegisterOperand get edi => RegisterOperandIntel('edi');
  RegisterOperand get eip => RegisterOperandIntel('eip');
}

class AsmBuilderIntel64 extends AsmBuilderIntel32 {
  RegisterOperand get rax => RegisterOperandIntel('rax');
  RegisterOperand get rbx => RegisterOperandIntel('rbx');
  RegisterOperand get rcx => RegisterOperandIntel('rcx');
  RegisterOperand get rdx => RegisterOperandIntel('rdx');
  RegisterOperand get rbp => RegisterOperandIntel('rbp');
  RegisterOperand get rsp => RegisterOperandIntel('rsp');
  RegisterOperand get rsi => RegisterOperandIntel('rsi');
  RegisterOperand get rdi => RegisterOperandIntel('rdi');
  RegisterOperand get r8 => RegisterOperandIntel('r8');
  RegisterOperand get r9 => RegisterOperandIntel('r9');
  RegisterOperand get r10 => RegisterOperandIntel('r10');
  RegisterOperand get r11 => RegisterOperandIntel('r11');
  RegisterOperand get r12 => RegisterOperandIntel('r12');
  RegisterOperand get r13 => RegisterOperandIntel('r13');
  RegisterOperand get r14 => RegisterOperandIntel('r14');
  RegisterOperand get r15 => RegisterOperandIntel('r15');
  RegisterOperand get rip => RegisterOperandIntel('rip');
}