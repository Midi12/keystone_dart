abstract class Operand {
  final dynamic value;

  const Operand(this.value);

  String format() => '$value';
}

abstract class RegisterOperand extends Operand {
  const RegisterOperand(String name) : super(name);
}

abstract class ImmediateValueOperand extends Operand {
  const ImmediateValueOperand(int value) : super(value);
}

abstract class MemoryValueOperand extends Operand {
  const MemoryValueOperand(int address) : super(address);
}