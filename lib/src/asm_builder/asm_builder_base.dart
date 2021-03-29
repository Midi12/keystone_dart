import 'package:keystone_dart/src/asm_builder/instruction.dart';

import 'operand.dart';

abstract class AsmBuilderBase {
  // ignore: prefer_final_fields
  String _asmString = '';

  AsmBuilderBase();

  String build() {
    return _asmString;
  }

  void reset() { _asmString = ''; }

  AsmBuilderBase append(Instruction inst) {
    _asmString += '${inst.format()};';
    return this;
  }

  AsmBuilderBase push(Operand op);
  AsmBuilderBase mov(Operand op1, Operand op2);
  AsmBuilderBase pop(Operand op);
}