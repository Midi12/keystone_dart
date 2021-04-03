import 'package:keystone_dart/src/asm_builder/asm_builder_base.dart';
import 'package:keystone_dart/src/asm_builder/instruction.dart';
import 'package:test/test.dart';

class AsmBuilder extends AsmBuilderBase {}

class Instruction1 extends Instruction {
  Instruction1(String name) : super(name);

  @override
  String format() => 'inst1 $name';
}

class Instruction2 extends Instruction {
  Instruction2(String name) : super(name);

  @override
  String format() => 'inst2 $name';
}

void main() {
  test('Append instructions', () {
    var builder = AsmBuilder();

    builder.append(Instruction1('test'));
    builder.append(Instruction2('test'));

    var asm = builder.build();
    expect(asm, 'inst1 test;inst2 test');
  });

  test('Append raw strings', () {
    var builder = AsmBuilder();

    builder.appendRaw('raw inst1');
    builder.appendRaw('raw inst2');

    var asm = builder.build();
    expect(asm, 'raw inst1;raw inst2');
  });
}