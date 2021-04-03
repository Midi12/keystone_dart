import 'package:keystone_dart/src/asm_builder/operand.dart';
import 'package:test/test.dart';

class Register extends RegisterOperand {
  Register(String name) : super(name);
}

class ImmediateValue extends ImmediateValueOperand {
  ImmediateValue(int value) : super(value);
}

class Dereferenced extends DereferencedOperand {
  Dereferenced(Operand item) : super(item);
}

void main() {

  test('RegisterOperand are formatted correctly', () {
    var rax = Register('rax');

    expect(rax.value, 'rax');
    expect(rax.format(), 'rax');
  });

  test('ImmediateValueOperand are formatted correctly', () {
    var imm = ImmediateValue(1234);

    expect(imm.value, 1234);
    expect(imm.format(), '1234');
  });

  test('ImmediateValueOperand (hex) are formatted correctly', () {
    var imm = ImmediateValue(0x1234);

    expect(imm.value, 0x1234);
    expect(imm.format(), '4660');
  });

  test('DereferencedOperand (imm) needs a formatter', () {
    var deref = Dereferenced(ImmediateValue(1234));

    expect(deref.value, TypeMatcher<ImmediateValue>());
    expect(() => deref.format(), throwsUnimplementedError);
  });

  test('DereferencedOperand (reg) needs a formatter', () {
    var deref = Dereferenced(Register('rax'));

    expect(deref.value, TypeMatcher<Register>());
    expect(() => deref.format(), throwsUnimplementedError);
  });
}