import 'instruction.dart';

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
  
  AsmBuilderBase add(Operand op1, Operand op2);
  AsmBuilderBase sub(Operand op1, Operand op2);
  AsmBuilderBase mul(Operand op1);
  AsmBuilderBase div(Operand op1);
  AsmBuilderBase inc(Operand op1);
  AsmBuilderBase dec(Operand op1);

  AsmBuilderBase call(Operand op1);
  AsmBuilderBase ret();

  AsmBuilderBase and(Operand op1, Operand op2);
  AsmBuilderBase or(Operand op1, Operand op2);
  AsmBuilderBase xor(Operand op1, Operand op2);
  AsmBuilderBase shl(Operand op1, Operand op2);
  AsmBuilderBase shr(Operand op1, Operand op2);

  AsmBuilderBase cmp(Operand op1, Operand op2);
  AsmBuilderBase je(Operand op1);
  AsmBuilderBase jne(Operand op1);
  AsmBuilderBase jg(Operand op1);
  AsmBuilderBase jge(Operand op1);
  AsmBuilderBase jl(Operand op1);
  AsmBuilderBase jle(Operand op1);
  AsmBuilderBase test(Operand op1, Operand op2);
  AsmBuilderBase jz(Operand op1);
  AsmBuilderBase jnz(Operand op1);
  AsmBuilderBase jmp(Operand op1);

  AsmBuilderBase nop();
}