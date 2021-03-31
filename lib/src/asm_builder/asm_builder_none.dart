import 'asm_builder_base.dart';
import 'instruction.dart';

class AsmBuilderNone extends AsmBuilderBase {

  @override
  String build() => throw UnimplementedError();

  @override
  void reset() => throw UnimplementedError();

  @override
  AsmBuilderBase append(Instruction inst) => throw UnimplementedError();

  @override
  AsmBuilderBase appendRaw(String raw) => throw UnimplementedError();
}