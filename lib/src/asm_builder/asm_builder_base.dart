import 'instruction.dart';

/// The base class to derive from when implementing assembler syntax helpers
abstract class AsmBuilderBase {
  List<String> _instructions = [];

  AsmBuilderBase();

  /// Builds the string to be assembled by the Keystone engine
  String build() {
    return _instructions.join(';');
  }

  /// Resets the instruction list
  void reset() {
    _instructions = [];
  }

  /// Appends an [instruction] to the instructions list
  AsmBuilderBase append(Instruction instruction) {
    _instructions.add(instruction.format());
    return this;
  }

  /// Appends a [raw] string to the instructions list
  AsmBuilderBase appendRaw(String raw) {
    _instructions.add(raw);
    return this;
  }
}
