import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import 'idisposable.dart';

import 'keystone_exports.dart';
import 'keystone_const.dart';

import 'asm_builder/asm_builder_base.dart';

/// The path where Keystone engine dependencies are located
String? keystonePath;

/// A class to handle and translate the Keystone engine errors
class KeystoneException implements Exception {
  late String _message;
  final int _code;

  /// `KeystoneException` constructor
  ///
  /// Builds the `message` from the provided [_code]
  KeystoneException(this._code) {
    var ptr = KsStrError(_code);
    _message = ptr.toDartString();
  }

  /// The error [code]
  int get code => _code;

  /// The translated [message] from the error `code`
  String get message => _message;

  /// The string representation of a `KeystoneException`
  @override
  String toString() => 'KeystoneException : $_code  ($_message)';
}

/// A result of the Keystone engine
///
/// This is an holder class
class AssemblerResult {
  final Uint8List _assembly;
  final int _size;
  final int _statements;
  final int _error;

  /// `AssemblerResult` constructor
  AssemblerResult(this._assembly, this._size, this._statements, this._error);

  /// The generated [assembly] by the Keystone engine
  Uint8List get assembly => _assembly;

  /// The [size] of the [assembly] list
  int get size => _size;

  /// The number of [statements] in the [assembly] list
  int get statements => _statements;

  /// The [error] code returned by the Keystone engine
  int get error => _error;

  /// The validity of the assembly result
  ///
  /// If the Keystone engine returns `KS_ERR_OK` the assembly is considered [valid]
  bool get valid => _error == KS_ERR_OK;
}

/// The [Keystone] engine bindings
///
/// The class must be disposed by calling `.dispose()` once not needed anymore to prevent memory leakage.
class Keystone implements IDisposable {
  Pointer<IntPtr> _engine = nullptr;
  int _syntax = -1;
  late final int _arch;
  late final int _mode;

  /// The [Keystone] engine constructor
  ///
  /// Throw an [Exception] on either failure to load the keystone engine dependencies or
  /// version mismatch. Throws a [KeystoneException] in case of wrong [architecture] and/or [mode].
  /// Any supported [architecture] and [mode] combination defined in `keystone_const.dart`.
  Keystone(int architecture, int mode) {
    if (!ensureLoaded(keystonePath)) {
      throw Exception('Unsupported operating system');
    }

    if (ksMakeVersion(KS_VERSION_MAJOR, KS_VERSION_MINOR) != version) {
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

  /// The current engine [architecture]
  int get architecture => _arch;

  /// The current engine [mode]
  int get mode => _mode;

  /// The current engine [syntax]
  int get syntax => _syntax;

  /// Cleanup the Keystone engine resources
  @override
  void dispose() {
    var err = KsClose(_engine.value);

    if (err != KS_ERR_OK) {
      throw KeystoneException(err);
    }

    calloc.free(_engine);
    _engine = nullptr;
  }

  /// The Keystone [version]
  int get version {
    var major = calloc.allocate<Uint32>(sizeOf<Uint32>());
    var minor = calloc.allocate<Uint32>(sizeOf<Uint32>());

    var combined = KsVersion(major, minor);

    calloc.free(minor);
    calloc.free(major);

    return combined;
  }

  /// The last engine error
  int get lastError {
    return KsErrno(_engine.value);
  }

  /// Sets the engine option ([type]) with the [value]
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

  /// Returns if the supplied [architecture] is supported by the engine
  bool isArchitectureSupported(int architecture) {
    return KsArchSupported(architecture);
  }

  /// Assemble code from the [builder] helper
  ///
  /// A base address is optional
  AssemblerResult assemble(AsmBuilderBase builder, {int baseAddress = 0}) {
    return assembleRaw(builder.build(), baseAddress: baseAddress);
  }

  /// Assemble code from a raw [asm] string
  ///
  /// A base address is optional
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
