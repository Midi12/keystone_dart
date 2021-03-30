import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import 'idisposable.dart';

import 'keystone_exports.dart';
import 'keystone_const.dart';

import 'asm_builder/asm_builder_base.dart';
import 'asm_builder/asm_builder_intel.dart' show AsmBuilderIntel;

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
  AsmBuilderBase? _asmBuilder;

  Keystone(int architecture, int mode) {
    if (!ensureLoaded(keystonePath)) {
      throw Exception('Unsupported operating system');
    }

    _engine = calloc.allocate(sizeOf<IntPtr>());

    var err = KsOpen(architecture, mode, _engine);
    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }
  }

  AsmBuilderBase? get builder => _asmBuilder;

  @override
  void dispose() {
    var err = KsClose(_engine.value);
    
    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    calloc.free(_engine);
    _engine = nullptr;
  }

  bool setOption(int type, int value) {
    var err = KsOption(_engine.value, type, value);

    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    if (type == KS_OPT_SYNTAX) {
      switch (value) {
        case KS_OPT_SYNTAX_INTEL:
          _asmBuilder = AsmBuilderIntel();
          break;
        case KS_OPT_SYNTAX_ATT:
        case KS_OPT_SYNTAX_NASM:
        case KS_OPT_SYNTAX_MASM:
        case KS_OPT_SYNTAX_GAS:
        case KS_OPT_SYNTAX_RADIX16:
        default:
          _asmBuilder = null;
          break;
      }
    }

    return err == KS_ERR_OK;
  }

  bool isArchitectureSupported(int architecture) {
    return KsArchSupported(architecture);
  }

  AssemblerResult assemble({ int baseAddress = 0 }) {
    return assembleRaw(_asmBuilder!.build(), baseAddress: baseAddress);
  }

  AssemblerResult assembleRaw(String asm, { int baseAddress = 0 }) {
    var data = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
    var size = calloc.allocate<IntPtr>(sizeOf<IntPtr>());
    var statements = calloc.allocate<IntPtr>(sizeOf<IntPtr>());

    var err = KsAsm(_engine.value, asm.toNativeUtf8(), baseAddress, data, size, statements);
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
      buildBuffer(data, size.value),
      size.value,
      statements.value,
      err
    );

    KsFree(data.value);

    calloc.free(statements);
    calloc.free(size);
    calloc.free(data);

    return result;
  }
}