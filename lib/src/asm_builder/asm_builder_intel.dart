import 'asm_builder_base.dart';
import 'instruction.dart';
import 'operand.dart';

class RegisterOperandIntel extends RegisterOperand {
  const RegisterOperandIntel(String name) : super(name);
}

const rax = RegisterOperandIntel('rax');
const rbx = RegisterOperandIntel('rbx');
const rcx = RegisterOperandIntel('rcx');
const rdx = RegisterOperandIntel('rdx');
const rbp = RegisterOperandIntel('rbp');
const rsp = RegisterOperandIntel('rsp');
const rsi = RegisterOperandIntel('rsi');
const rdi = RegisterOperandIntel('rdi');
const r8 = RegisterOperandIntel('r8');
const r9 = RegisterOperandIntel('r9');
const r10 = RegisterOperandIntel('r10');
const r11 = RegisterOperandIntel('r11');
const r12 = RegisterOperandIntel('r12');
const r13 = RegisterOperandIntel('r13');
const r14 = RegisterOperandIntel('r14');
const r15 = RegisterOperandIntel('r15');
const rip = RegisterOperandIntel('rip');

const eax = RegisterOperandIntel('eax');
const ebx = RegisterOperandIntel('ebx');
const ecx = RegisterOperandIntel('ecx');
const edx = RegisterOperandIntel('edx');
const ebp = RegisterOperandIntel('ebp');
const esp = RegisterOperandIntel('esp');
const esi = RegisterOperandIntel('esi');
const edi = RegisterOperandIntel('edi');

const ax = RegisterOperandIntel('ax');
const bx = RegisterOperandIntel('bx');
const cx = RegisterOperandIntel('cx');
const dx = RegisterOperandIntel('dx');
const bp = RegisterOperandIntel('bp');
const sp = RegisterOperandIntel('sp');
const si = RegisterOperandIntel('si');
const di = RegisterOperandIntel('di');

const ah = RegisterOperandIntel('ah');
const bh = RegisterOperandIntel('bh');
const ch = RegisterOperandIntel('ch');
const dh = RegisterOperandIntel('dh');

const al = RegisterOperandIntel('al');
const bl = RegisterOperandIntel('bl');
const cl = RegisterOperandIntel('cl');
const dl = RegisterOperandIntel('dl');

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
  String format() => '[$value]';
}

ImmediateValueOperand imm(int value) => ImmediateValueOperandIntel(value);
MemoryValueOperand mem(dynamic item) => MemoryValueOperandIntel(item);
DereferencedOperand deref(Operand item) => DereferencedOperandIntel(item);

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
  @override
  AsmBuilderBase mov(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('mov', dest, src));
    return this;
  }

  @override
  AsmBuilderBase pop(Operand reg) {
    append(OneOperandInstructionIntel('pop', reg));
    return this;
  }

  @override
  AsmBuilderBase push(Operand item) {
    append(OneOperandInstructionIntel('push', item));
    return this;
  }

  @override
  AsmBuilderBase add(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('add', dest, src));
    return this;
  }

  @override
  AsmBuilderBase and(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('and', dest, src));
    return this;
  }

  @override
  AsmBuilderBase call(Operand label) {
    append(OneOperandInstructionIntel('call', label));
    return this;
  }

  @override
  AsmBuilderBase cmp(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('cmp', op1, op2));
    return this;
  }

  @override
  AsmBuilderBase dec(Operand dest) {
    append(OneOperandInstructionIntel('dec', dest));
    return this;
  }

  @override
  AsmBuilderBase div(Operand reg) {
    append(OneOperandInstructionIntel('div', reg));
    return this;
  }

  @override
  AsmBuilderBase inc(Operand dest) {
    append(OneOperandInstructionIntel('inc', dest));
    return this;
  }

  @override
  AsmBuilderBase je(Operand label) {
    append(OneOperandInstructionIntel('je', label));
    return this;
  }

  @override
  AsmBuilderBase jg(Operand label) {
    append(OneOperandInstructionIntel('jg', label));
    return this;
  }

  @override
  AsmBuilderBase jge(Operand label) {
    append(OneOperandInstructionIntel('jge', label));
    return this;
  }

  @override
  AsmBuilderBase jl(Operand label) {
    append(OneOperandInstructionIntel('jl', label));
    return this;
  }

  @override
  AsmBuilderBase jle(Operand label) {
    append(OneOperandInstructionIntel('jle', label));
    return this;
  }

  @override
  AsmBuilderBase jmp(Operand label) {
    append(OneOperandInstructionIntel('jmp', label));
    return this;
  }

  @override
  AsmBuilderBase jne(Operand label) {
    append(OneOperandInstructionIntel('jne', label));
    return this;
  }

  @override
  AsmBuilderBase jnz(Operand label) {
    append(OneOperandInstructionIntel('jnz', label));
    return this;
  }

  @override
  AsmBuilderBase jz(Operand label) {
    append(OneOperandInstructionIntel('jz', label));
    return this;
  }

  @override
  AsmBuilderBase mul(Operand reg) {
    append(OneOperandInstructionIntel('mul', reg));
    return this;
  }

  @override
  AsmBuilderBase nop() {
    append(ZeroOperandInstructionIntel('nop'));
    return this;
  }

  @override
  AsmBuilderBase or(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('or', dest, src));
    return this;
  }

  @override
  AsmBuilderBase ret() {
    append(ZeroOperandInstructionIntel('ret'));
    return this;
  }

  @override
  AsmBuilderBase shl(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shl', dest, count));
    return this;
  }

  @override
  AsmBuilderBase shr(Operand dest, Operand count) {
    append(TwoOperandsInstructionIntel('shr', dest, count));
    return this;
  }

  @override
  AsmBuilderBase sub(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('sub', dest, src));
    return this;
  }

  @override
  AsmBuilderBase test(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('test', op1, op2));
    return this;
  }

  @override
  AsmBuilderBase xor(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('xor', dest, src));
    return this;
  }
}