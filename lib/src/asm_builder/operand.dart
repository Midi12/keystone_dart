/// An abstract class representing an operand
abstract class Operand {
  final dynamic value;

  const Operand(this.value);

  /// Returns the operand formatted to its syntaxic representation
  String format() => '$value';
}

/// An abstract class representing a register
abstract class RegisterOperand extends Operand {
  const RegisterOperand(String name) : super(name);
}

/// An abstract class representing an immediate value
abstract class ImmediateValueOperand extends Operand {
  const ImmediateValueOperand(int value) : super(value);
}

/// An abstract class representing a memory value
abstract class MemoryValueOperand extends Operand {
  const MemoryValueOperand(dynamic item) : super(item);
}

/// An abstract class representing a dereferenced operand
abstract class DereferencedOperand extends Operand {
  const DereferencedOperand(Operand item) : super(item);

  @override
  String format() => throw UnimplementedError();
}

/// An abstract class representing a label
abstract class LabelOperand extends Operand {
  const LabelOperand(value) : super(value);

  @override
  String format() => '$value';
}
