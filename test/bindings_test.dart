import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:test/test.dart';

import 'package:keystone_dart/src/keystone_const.dart';
import 'package:keystone_dart/src/keystone_exports.dart';

Uint8List _copyBuffer(Pointer<IntPtr> ptr, int size) {
  var buffer = Uint8List(size);

  // get a view on the inner ptr
  var innerPtr = Pointer<Uint8>.fromAddress(ptr.value);
  var view = innerPtr.asTypedList(size);
  
  // copy view to buffer
  for (var i = 0; i < size; i++) {
    buffer[i] = view[i];
  }

  return buffer;
}

void _test_engine(int arch, int mode, String code, int? syntax, List<int> expectedBytes) {
  var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

  var err = KsOpen(arch, mode, ppEngine);

  if (syntax != null) {
    err = KsOption(ppEngine.value, KS_OPT_SYNTAX, syntax);
  }

  var pEncoding = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
  var pSize = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
  var pStatements = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

  var pCode = code.toNativeUtf8();
  err = KsAsm(ppEngine.value, pCode, 0, pEncoding, pSize, pStatements);

  expect(err, KS_ERR_OK);
  expect(pSize.value, isPositive);
  expect(pStatements.value, isPositive);
  expect(_copyBuffer(pEncoding, pSize.value).toList(), expectedBytes);

  calloc.free(pCode);
  calloc.free(pStatements);
  calloc.free(pSize);
  calloc.free(pEncoding);

  err = KsClose(ppEngine.value);

  calloc.free(ppEngine);
}

void main() {

  setUpAll(() {
    ensureLoaded('dependencies/keystone/x64/');
  });

  test('KsVersion returns correct values', () {
    var major = calloc.allocate<Uint32>(sizeOf<Uint32>());
    var minor = calloc.allocate<Uint32>(sizeOf<Uint32>());

    var combined = KsVersion(major, minor);

    expect(major.value, KS_VERSION_MAJOR);
    expect(minor.value, KS_VERSION_MINOR);
    expect(ksMakeVersion(major.value, minor.value), combined);
    expect(combined, ksMakeVersion(KS_VERSION_MAJOR, KS_VERSION_MINOR));

    calloc.free(minor);
    calloc.free(major);
  });

  test('KsOpen returns a valid pointer and KsClose returns no error', () {
    var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(KS_ARCH_X86, KS_MODE_64, ppEngine);

    expect(err, KS_ERR_OK);
    expect(ppEngine.value, isNonZero);

    err = KsClose(ppEngine.value);

    expect(err, KS_ERR_OK);

    calloc.free(ppEngine);
  });

  test('KsOpen returns invalid architecture error', () {
    var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(999, KS_MODE_64, ppEngine);

    expect(err, KS_ERR_ARCH);
    expect(ppEngine.value, isZero);

    calloc.free(ppEngine);
  });

  test('KsOpen returns invalid mode error', () {
    var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(KS_ARCH_X86, 999, ppEngine);

    expect(err, KS_ERR_MODE);
    expect(ppEngine.value, isZero);

    calloc.free(ppEngine);
  });

  test('KsArchSupported returns true', () {
    var supported = KsArchSupported(KS_ARCH_X86);
    expect(supported, isTrue);
  });

  test('KsArchSupported return false', () {
    var supported = KsArchSupported(999);
    expect(supported, isFalse);
  });

  test('KsOption returns success', () {
    var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(KS_ARCH_X86, KS_MODE_64, ppEngine);

    err = KsOption(ppEngine.value, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    expect(err, KS_ERR_OK);

    err = KsClose(ppEngine.value);

    calloc.free(ppEngine);
  });

  test('KsOption returns failure', () {
    var ppEngine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(KS_ARCH_X86, KS_MODE_64, ppEngine);

    err = KsOption(ppEngine.value, 999, KS_OPT_SYNTAX_INTEL);
    expect(err, KS_ERR_OPT_INVALID);

    err = KsOption(ppEngine.value, KS_OPT_SYNTAX, 999);
    expect(err, KS_ERR_OPT_INVALID);

    err = KsClose(ppEngine.value);

    calloc.free(ppEngine);
  });

  test('KsAsm returns valid assembler for X86 64 (Intel)', () => _test_engine(KS_ARCH_X86, KS_MODE_64, 'push rax; mov rax, 1; pop rax;', KS_OPT_SYNTAX_INTEL, [0x50, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x58]));

  test('KsAsm returns valid assembler for X86 32 (Intel)', () => _test_engine(KS_ARCH_X86, KS_MODE_32, 'push eax; mov eax, 1; pop eax', KS_OPT_SYNTAX_INTEL, [0x50, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x58]));

  test('KsAsm returns valid assembler for X86 16 (Intel)', () => _test_engine(KS_ARCH_X86, KS_MODE_16, 'push ax; mov ax, 1; pop ax;', KS_OPT_SYNTAX_INTEL, [0x50, 0xB8, 0x01, 0x00, 0x58]));

  test('KsAsm returns valid assembler for X86 64 (AT&T)', () => _test_engine(KS_ARCH_X86, KS_MODE_64, 'push %rax; movq \$0x1, %rax; pop %rax;', KS_OPT_SYNTAX_ATT, [0x50, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x58]));

  test('KsAsm returns valid assembler for X86 32 (AT&T)', () => _test_engine(KS_ARCH_X86, KS_MODE_32, 'push %eax; movl \$1, %eax; pop %eax;', KS_OPT_SYNTAX_ATT, [0x50, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x58]));

  test('KsAsm returns valid assembler for X86 16 (AT&T)', () => _test_engine(KS_ARCH_X86, KS_MODE_16, 'push %ax; movw \$1, %ax; pop %ax;', KS_OPT_SYNTAX_ATT, [0x50, 0xB8, 0x01, 0x00, 0x58]));

  test('KsAsm returns valid assembler for ARM', () => _test_engine(KS_ARCH_ARM, KS_MODE_ARM, 'str r0, [sp, #-4]!; mov r0, #1; ldr r0, [sp], #4', null, [0x04, 0x00, 0x2D, 0xE5, 0x01, 0x00, 0xA0, 0xE3, 0x04, 0x00, 0x9D, 0xE4]));

  test('KsAsm returns valid assembler for ARM64', () => _test_engine(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, 'str x0, [sp, #-0x10]!;mov x0, #1;ldr x0, [sp, #0x10]', null, [0xE0, 0x0F, 0x1F, 0xF8, 0x20, 0x00, 0x80, 0xD2, 0xE0, 0x0B, 0x40, 0xF9]));

}
