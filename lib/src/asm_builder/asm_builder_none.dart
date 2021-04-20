import 'asm_builder_base.dart';
import 'instruction.dart';

/// A none asm builder helper
class AsmBuilderNone extends AsmBuilderBase {
  /// Unimplemented on purpose
  @override
  String build() => throw UnimplementedError();

  /// Unimplemented on purpose
  @override
  void reset() => throw UnimplementedError();

  /// Unimplemented on purpose
  @override
  AsmBuilderBase append(Instruction inst) => throw UnimplementedError();

  /// Unimplemented on purpose
  @override
  AsmBuilderBase appendRaw(String raw) => throw UnimplementedError();
}
