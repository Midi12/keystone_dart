/// An abstract class representing an instruction
abstract class Instruction {
  final String name;

  const Instruction(this.name);

  String format() => throw UnimplementedError();
}
