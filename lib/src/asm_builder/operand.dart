abstract class Operand {
  final dynamic value;

  const Operand(this.value);

  String format() => '$value';
}

class RegisterOperand extends Operand {
  const RegisterOperand(String name) : super(name);
}

class ImmediateValueOperand extends Operand {
  const ImmediateValueOperand(int value) : super(value);
}