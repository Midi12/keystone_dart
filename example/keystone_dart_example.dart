import 'dart:io' show Platform;

import 'package:keystone_dart/keystone_dart.dart' as ks;
import 'package:keystone_dart/src/asm_builder/asm_builder_intel.dart' as intel;

void main() {
  print(Platform.script);

  // setup library path (must have ending slash)
  ks.keystonePath = 'dependencies/keystone/x64/';

  ks.Keystone? engine;

  try {
    // Start Keystone engine
    engine = ks.Keystone(ks.KS_ARCH_X86, ks.KS_MODE_64);

    // Set Intel syntax
    engine.setOption(ks.KS_OPT_SYNTAX, ks.KS_OPT_SYNTAX_INTEL);

    var isx8664Supported = engine.isArchitectureSupported(ks.KS_ARCH_X86);
    print('x86-64 supported ? $isx8664Supported');

    var code = 'push rax; mov rax, 1; pop rax;';
    var res = engine.assembleRaw(code);
    print('assembly valid ? ${res.valid}');

    var bytes = res.assembly.map((byte) => byte.toRadixString(16)).join(' ');
    print('assembly for $code -> $bytes');

    engine.builder!.push(intel.rax);
    engine.builder!.mov(intel.rax, intel.imm(1));
    engine.builder!.append(intel.TwoOperandsInstructionIntel('sub', intel.eax, intel.imm(1)));
    engine.builder!.pop(intel.rax);
    engine.builder!.nop();
    engine.builder!.append(intel.ZeroOperandInstructionIntel('nop'));
    engine.builder!.appendRaw('ret');
    var res2 = engine.assemble();

    print('assembly 2 valid ? ${res2.valid}');

    var bytes2 = res2.assembly.map((byte) => byte.toRadixString(16)).join(' ');
    print('assembly for built asm -> $bytes2');

  } on ks.KeystoneException catch (e) {
    print('Error $e');
  } finally {
    engine?.dispose();
  }
}
