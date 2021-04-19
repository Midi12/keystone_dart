import 'instruction.dart';

abstract class AsmBuilderBase {
  List<String> _instructions = [];

  AsmBuilderBase();

  String build() {
    return _instructions.join(';');
  }

  void reset() {
    _instructions = [];
  }

  AsmBuilderBase append(Instruction inst) {
    _instructions.add(inst.format());
    return this;
  }

  AsmBuilderBase appendRaw(String raw) {
    _instructions.add(raw);
    return this;
  }
}
