import 'instruction.dart';

abstract class AsmBuilderBase {
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

  AsmBuilderBase appendRaw(String raw) {
    _asmString += '$raw;';
    return this;
  }
}