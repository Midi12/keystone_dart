import 'package:keystone_dart/keystone_dart.dart';
import 'package:test/test.dart';

void main() {
  late Keystone ks;

  setUpAll(() {
    keystonePath = 'dependencies/keystone/x64/';
    ks = Keystone(KS_ARCH_X86, KS_MODE_64);
  });

  tearDownAll(() => ks.dispose());

  test('test version', () {
    expect(ks.version(), ksMakeVersion(KS_VERSION_MAJOR, KS_VERSION_MINOR));
  });

  test('test setOption', () {
    // expect(ks.setOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_MASM), true);
    expect(ks.setOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT), true);
    expect(ks.setOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL), true);
    expect(ks.setOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM), true);
    expect(() => ks.setOption(KS_OPT_SYNTAX, 999),
        throwsA(isA<KeystoneException>()));
  });

  test('test assembler', () {
    ks.setOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);

    var a = AsmBuilderIntel64();

    a.push(a.rax);
    a.mov(a.rax, a.imm(12));
    a.pop(a.rax);

    var res = ks.assemble(a);
    expect(res, TypeMatcher<AssemblerResult>());
    expect(
        res.assembly, [0x50, 0x48, 0xC7, 0xC0, 0x12, 0x00, 0x00, 0x00, 0x58]);
    expect(res.statements, 3);
    expect(res.size, 9);
  });
}
