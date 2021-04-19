import 'package:test/test.dart';

import 'package:keystone_dart/keystone_dart.dart';

void main() {
  test('ImmediateValueOperandIntel', () {
    var imm = ImmediateValueOperandIntel(0xFFFF);

    expect(imm.value, 0xFFFF);
    expect(imm.format(), '65535');
    expect(imm, TypeMatcher<ImmediateValueOperandIntel>());
  });

  test('RegisterOperandIntel', () {
    var reg = RegisterOperandIntel('rax');

    expect(reg.value, 'rax');
    expect(reg.format(), 'rax');
    expect(reg, TypeMatcher<RegisterOperandIntel>());
  });

  // test('MemoryValueOperandIntel', () {});

  test('DereferencedOperandIntel', () {
    var deref_imm =
        DereferencedOperandIntel(ImmediateValueOperandIntel(0xFFFF));

    expect(deref_imm.format(), '[65535]');
    expect(deref_imm, TypeMatcher<DereferencedOperandIntel>());
    expect(deref_imm.value, TypeMatcher<ImmediateValueOperandIntel>());

    var deref_reg = DereferencedOperandIntel(RegisterOperandIntel('rax'));

    expect(deref_reg.format(), '[rax]');
    expect(deref_reg, TypeMatcher<DereferencedOperandIntel>());
    expect(deref_reg.value, TypeMatcher<RegisterOperandIntel>());
  });

  test('ZeroOperandInstructionIntel', () {
    var zero_op_inst = ZeroOperandInstructionIntel('nop');

    expect(zero_op_inst.name, 'nop');
    expect(zero_op_inst.format(), 'nop');
    expect(zero_op_inst, TypeMatcher<ZeroOperandInstructionIntel>());
  });

  test('OneOperandInstructionIntel', () {
    var one_op_inst_imm =
        OneOperandInstructionIntel('push', ImmediateValueOperandIntel(1234));

    expect(one_op_inst_imm.name, 'push');
    expect(one_op_inst_imm.format(), 'push 1234');
    expect(one_op_inst_imm, TypeMatcher<OneOperandInstructionIntel>());

    var one_op_inst_reg =
        OneOperandInstructionIntel('push', RegisterOperandIntel('rax'));

    expect(one_op_inst_reg.name, 'push');
    expect(one_op_inst_reg.format(), 'push rax');
    expect(one_op_inst_reg, TypeMatcher<OneOperandInstructionIntel>());

    var one_op_inst_deref = OneOperandInstructionIntel(
        'lea', DereferencedOperandIntel(RegisterOperandIntel('rax')));

    expect(one_op_inst_deref.name, 'lea');
    expect(one_op_inst_deref.format(), 'lea [rax]');
    expect(one_op_inst_deref, TypeMatcher<OneOperandInstructionIntel>());
  });

  test('TwoOperandsInstructionIntel', () {
    var two_op_inst_reg_imm = TwoOperandsInstructionIntel(
        'mov', RegisterOperandIntel('rax'), ImmediateValueOperandIntel(1234));

    expect(two_op_inst_reg_imm.name, 'mov');
    expect(two_op_inst_reg_imm.format(), 'mov rax, 1234');
    expect(two_op_inst_reg_imm, TypeMatcher<TwoOperandsInstructionIntel>());

    var two_op_inst_deref = TwoOperandsInstructionIntel(
        'mov',
        RegisterOperandIntel('rax'),
        DereferencedOperandIntel(RegisterOperandIntel('rax')));

    expect(two_op_inst_deref.name, 'mov');
    expect(two_op_inst_deref.format(), 'mov rax, [rax]');
    expect(two_op_inst_deref, TypeMatcher<TwoOperandsInstructionIntel>());
  });

  test('AsmBuilderIntel.imm', () {
    var a = AsmBuilderIntel();

    var imm = a.imm(0xFFFF);

    expect(imm, TypeMatcher<ImmediateValueOperandIntel>());
    expect(imm.value, 0xFFFF);
    expect(imm.format(), '65535');
  });

  // test('AsmBuilderIntel.mem', () {});

  test('AsmBuilderIntel.deref', () {
    var a = AsmBuilderIntel64();

    var deref_imm = a.deref(a.imm(0xFFFF));

    expect(deref_imm, TypeMatcher<DereferencedOperandIntel>());
    expect(deref_imm.format(), '[65535]');

    var deref_reg = a.deref(a.rax);

    expect(deref_reg, TypeMatcher<DereferencedOperandIntel>());
    expect(deref_reg.format(), '[rax]');
  });

  test('AsmBuilderIntel.mov', () {
    var a = AsmBuilderIntel64();

    a.mov(a.rax, a.imm(0xFFFF));
    a.mov(a.rax, a.rbx);
    a.mov(a.rax, a.deref(a.rax));
    a.mov(a.rax, a.deref(a.imm(0xFFFF)));

    expect(a.build(),
        'mov rax, 65535;mov rax, rbx;mov rax, [rax];mov rax, [65535]');
  });

  test('AsmBuilderIntel.pop', () {
    var a = AsmBuilderIntel64();

    a.pop(a.rax);

    expect(a.build(), 'pop rax');
  });

  test('AsmBuilderIntel.push', () {
    var a = AsmBuilderIntel64();

    a.push(a.imm(0xFFFF));
    a.push(a.rax);

    expect(a.build(), 'push 65535;push rax');
  });

  test('AsmBuilderIntel.add', () {
    var a = AsmBuilderIntel64();

    a.add(a.rax, a.imm(1));

    expect(a.build(), 'add rax, 1');
  });

  test('AsmBuilderIntel.and', () {
    var a = AsmBuilderIntel64();

    a.and(a.rax, a.imm(1));

    expect(a.build(), 'and rax, 1');
  });

  test('AsmBuilderIntel.call', () {
    var a = AsmBuilderIntel64();

    a.call(a.rax);
    a.call(a.imm(0xFFFF));
    a.call(a.deref(a.rax));

    expect(a.build(), 'call rax;call 65535;call [rax]');
  });

  test('AsmBuilderIntel.cmp', () {
    var a = AsmBuilderIntel64();

    a.cmp(a.rax, a.imm(1));

    expect(a.build(), 'cmp rax, 1');
  });

  test('AsmBuilderIntel.dec', () {
    var a = AsmBuilderIntel64();

    a.dec(a.rax);

    expect(a.build(), 'dec rax');
  });

  test('AsmBuilderIntel.div', () {
    var a = AsmBuilderIntel64();

    a.div(a.rax);

    expect(a.build(), 'div rax');
  });

  test('AsmBuilderIntel.inc', () {
    var a = AsmBuilderIntel64();

    a.inc(a.rax);

    expect(a.build(), 'inc rax');
  });

  test('AsmBuilderIntel.je', () {
    var a = AsmBuilderIntel64();

    a.je(a.lab('lbl'));

    expect(a.build(), 'je lbl');
  });

  test('AsmBuilderIntel.jg', () {
    var a = AsmBuilderIntel64();

    a.jg(a.lab('lbl'));

    expect(a.build(), 'jg lbl');
  });

  test('AsmBuilderIntel.jge', () {
    var a = AsmBuilderIntel64();

    a.jge(a.lab('lbl'));

    expect(a.build(), 'jge lbl');
  });

  test('AsmBuilderIntel.jl', () {
    var a = AsmBuilderIntel64();

    a.jl(a.lab('lbl'));

    expect(a.build(), 'jl lbl');
  });

  test('AsmBuilderIntel.jle', () {
    var a = AsmBuilderIntel64();

    a.jle(a.lab('lbl'));

    expect(a.build(), 'jle lbl');
  });

  test('AsmBuilderIntel.jmp', () {
    var a = AsmBuilderIntel64();

    a.jmp(a.lab('lbl'));
    a.jmp(a.imm(1234));

    expect(a.build(), 'jmp lbl;jmp 1234');
  });

  test('AsmBuilderIntel.jne', () {
    var a = AsmBuilderIntel64();

    a.jne(a.lab('lbl'));

    expect(a.build(), 'jne lbl');
  });

  test('AsmBuilderIntel.jnz', () {
    var a = AsmBuilderIntel64();

    a.jnz(a.lab('lbl'));

    expect(a.build(), 'jnz lbl');
  });

  test('AsmBuilderIntel.jz', () {
    var a = AsmBuilderIntel64();

    a.jz(a.lab('lbl'));

    expect(a.build(), 'jz lbl');
  });

  test('AsmBuilderIntel.mul', () {
    var a = AsmBuilderIntel64();

    a.mul(a.rax);

    expect(a.build(), 'mul rax');
  });

  test('AsmBuilderIntel.nop', () {
    var a = AsmBuilderIntel64();

    a.nop();

    expect(a.build(), 'nop');
  });

  test('AsmBuilderIntel.or', () {
    var a = AsmBuilderIntel64();

    a.or(a.rax, a.imm(12));

    expect(a.build(), 'or rax, 12');
  });

  test('AsmBuilderIntel.ret', () {
    var a = AsmBuilderIntel64();

    a.ret();

    expect(a.build(), 'ret');
  });

  test('AsmBuilderIntel.shl', () {
    var a = AsmBuilderIntel64();

    a.shl(a.rax, a.imm(8));

    expect(a.build(), 'shl rax, 8');
  });

  test('AsmBuilderIntel.shr', () {
    var a = AsmBuilderIntel64();

    a.shr(a.rax, a.imm(8));

    expect(a.build(), 'shr rax, 8');
  });

  test('AsmBuilderIntel.sub', () {
    var a = AsmBuilderIntel64();

    a.sub(a.rax, a.rbx);

    expect(a.build(), 'sub rax, rbx');
  });

  test('AsmBuilderIntel.test', () {
    var a = AsmBuilderIntel64();

    a.test(a.rax, a.rbx);

    expect(a.build(), 'test rax, rbx');
  });

  test('AsmBuilderIntel.xor', () {
    var a = AsmBuilderIntel64();

    a.xor(a.eax, a.eax);

    expect(a.build(), 'xor eax, eax');
  });

  //test('', () {});
}
