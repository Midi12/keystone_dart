import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import 'idisposable.dart';

import 'keystone_exports.dart';
import 'keystone_const.dart';

import 'asm_builder/asm_builder_base.dart';

String? keystonePath;

class KeystoneException implements Exception {
  late String _message;
  final int _code;

  KeystoneException(this._code) {
    var ptr = KsStrError(_code);
    _message = ptr.toDartString();
  }

  int get code => _code;
  String get message => _message;

  @override
  String toString() => 'KeystoneException : $_code  ($_message)';
}

class AssemblerResult {
  final Uint8List _assembly;
  final int _size;
  final int _statements;
  final int _error;

  AssemblerResult(this._assembly, this._size, this._statements, this._error);

  Uint8List get assembly => _assembly;
  int get size => _size;
  int get statements => _statements;
  int get error => _error;
  bool get valid => _error == KS_ERR_OK;
}

class Keystone implements IDisposable {
  Pointer<IntPtr> _engine = nullptr;
  int _syntax = -1;
  late final int _arch;
  late final int _mode;

  Keystone(int architecture, int mode) {
    if (!ensureLoaded(keystonePath)) {
      throw Exception('Unsupported operating system');
    }

    if (ksMakeVersion(KS_VERSION_MAJOR, KS_VERSION_MINOR) != version()) {
      throw Exception('Version mismatch');
    }

    _engine = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsOpen(architecture, mode, _engine);
    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    _arch = architecture;
    _mode = mode;
  }

  int get architecture => _arch;
  int get mode => _mode;
  int get syntax => _syntax;

  @override
  void dispose() {
    var err = KsClose(_engine.value);

    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    calloc.free(_engine);
    _engine = nullptr;
  }

  int version() {
    var major = calloc.allocate<Uint32>(sizeOf<Uint32>());
    var minor = calloc.allocate<Uint32>(sizeOf<Uint32>());

    var combined = KsVersion(major, minor);

    calloc.free(minor);
    calloc.free(major);

    return combined;
  }

  int lastError() {
    return KsErrno(_engine.value);
  }

  bool setOption(int type, int value) {
    var err = KsOption(_engine.value, type, value);

    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    if (type == KS_OPT_SYNTAX) {
      _syntax = value;
    }

    return err == KS_ERR_OK;
  }

  bool isArchitectureSupported(int architecture) {
    return KsArchSupported(architecture);
  }

  AssemblerResult assemble(AsmBuilderBase builder, {int baseAddress = 0}) {
    return assembleRaw(builder.build(), baseAddress: baseAddress);
  }

  AssemblerResult assembleRaw(String asm, {int baseAddress = 0}) {
    var data = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
    var size = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
    var statements = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
    var code = asm.toNativeUtf8();

    var err = KsAsm(_engine.value, code, baseAddress, data, size, statements);
    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    Uint8List buildBuffer(Pointer<IntPtr> ptr, int size) {
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

    var result = AssemblerResult(
        buildBuffer(data, size.value), size.value, statements.value, err);

    KsFree(data.value);

    calloc.free(code);
    calloc.free(statements);
    calloc.free(size);
    calloc.free(data);

    return result;
  }
}
