import 'asm_builder_base.dart';
import 'instruction.dart';
import 'operand.dart';

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
  AsmBuilderBase mov(Operand op1, Operand op2) {
    append(TwoOperandsInstructionIntel('mov', op1, op2));
    return this;
  }

  @override
  AsmBuilderBase pop(Operand op) {
    append(OneOperandInstructionIntel('pop', op));
    return this;
  }

  @override
  AsmBuilderBase push(Operand op) {
    append(OneOperandInstructionIntel('push', op));
    return this;
  }
}