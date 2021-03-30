import 'asm_builder_base.dart';
import 'instruction.dart';
import 'operand.dart';

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
  AsmBuilderBase test(Operand reg, Operand imm) {
    append(TwoOperandsInstructionIntel('test', reg, imm));
    return this;
  }

  @override
  AsmBuilderBase xor(Operand dest, Operand src) {
    append(TwoOperandsInstructionIntel('xor', dest, src));
    return this;
  }
}