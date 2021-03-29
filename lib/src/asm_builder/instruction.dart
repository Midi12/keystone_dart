abstract class Instruction {
  final String name;

  const Instruction(this.name);

  String format() => throw UnimplementedError();
}