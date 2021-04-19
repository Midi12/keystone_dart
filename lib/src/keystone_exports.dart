import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

class ExportMap {
  final Map<String, String> _map = <String, String>{};

  ExportMap(Map<String, String> map) {
    _map.addAll(map);
  }

  String? operator [](String index) => _map[index];
}

class WindowsExportMap extends ExportMap {
  WindowsExportMap()
      : super({
          'ks_version': 'ks_version',
          'ks_open': 'ks_open',
          'ks_close': 'ks_close',
          'ks_free': 'ks_free',
          'ks_strerror': 'ks_strerror',
          'ks_errno': 'ks_errno',
          'ks_arch_supported': 'ks_arch_supported',
          'ks_option': 'ks_option',
          'ks_asm': 'ks_asm',
        });
}

class LinuxExportMap extends ExportMap {
  LinuxExportMap()
      : super({
          'ks_version': 'ks_version',
          'ks_open': 'ks_open',
          'ks_close': 'ks_close',
          'ks_free': 'ks_free',
          'ks_strerror': 'ks_strerror',
          'ks_errno': 'ks_errno',
          'ks_arch_supported': 'ks_arch_supported',
          'ks_option': 'ks_option',
          'ks_asm': 'ks_asm',
        });
}

class MacosExportMap extends ExportMap {
  MacosExportMap()
      : super({
          'ks_version': 'ks_version',
          'ks_open': 'ks_open',
          'ks_close': 'ks_close',
          'ks_free': 'ks_free',
          'ks_strerror': 'ks_strerror',
          'ks_errno': 'ks_errno',
          'ks_arch_supported': 'ks_arch_supported',
          'ks_option': 'ks_option',
          'ks_asm': 'ks_asm',
        });
}

DynamicLibrary? _keystone;
ExportMap? _exportMap;

const windows = 'windows';
const linux = 'linux';
const macos = 'macos';

bool ensureLoaded(String? libraryPath) {
  var libPath = libraryPath ?? '';

  switch (Platform.operatingSystem) {
    case windows:
      libPath =
          Directory.current.uri.resolve('${libPath}keystone.dll').toFilePath();
      _exportMap = WindowsExportMap();
      break;
    case linux:
      libPath =
          Directory.current.uri.resolve('${libPath}keystone.so').toFilePath();
      _exportMap = LinuxExportMap();
      break;
    case macos:
      libPath = Directory.current.uri
          .resolve('${libPath}keystone.dylib')
          .toFilePath();
      _exportMap = MacosExportMap();
      break;
    default:
      break;
  }

  _keystone = DynamicLibrary.open(libPath);

  return _keystone != null && _keystone?.handle != nullptr;
}

// Typedef format
// XXX_t : native function typedef
// XXX_d : dart function typedef

typedef KsVersion_t = Uint32 Function(Pointer<Uint32>, Pointer<Uint32>);
typedef KsVersion_d = int Function(Pointer<Uint32>, Pointer<Uint32>);
KsVersion_d? _pfnKsVersion;

int KsVersion(Pointer<Uint32> major, Pointer<Uint32> minor) {
  _pfnKsVersion ??= _keystone
      ?.lookupFunction<KsVersion_t, KsVersion_d>(_exportMap!['ks_version']!);
  return _pfnKsVersion!(major, minor);
}

typedef KsOpen_t = Uint32 Function(Uint32, Int32, Pointer<IntPtr>);
typedef KsOpen_d = int Function(int, int, Pointer<IntPtr>);
KsOpen_d? _pfnKsOpen;

int KsOpen(int architecture, int mode, Pointer<IntPtr> engine) {
  _pfnKsOpen ??=
      _keystone?.lookupFunction<KsOpen_t, KsOpen_d>(_exportMap!['ks_open']!);
  return _pfnKsOpen!(architecture, mode, engine);
}

typedef KsClose_t = Uint32 Function(IntPtr);
typedef KsClose_d = int Function(int);
KsClose_d? _pfnKsClose;

int KsClose(int engine) {
  _pfnKsClose ??=
      _keystone?.lookupFunction<KsClose_t, KsClose_d>(_exportMap!['ks_close']!);
  return _pfnKsClose!(engine);
}

typedef KsFree_t = Void Function(IntPtr);
typedef KsFree_d = void Function(int);
KsFree_d? _pfnKsFree;

void KsFree(int buffer) {
  _pfnKsFree ??=
      _keystone?.lookupFunction<KsFree_t, KsFree_d>(_exportMap!['ks_free']!);
  return _pfnKsFree!(buffer);
}

typedef KsStrError_t = Pointer<Utf8> Function(Uint32);
typedef KsStrError_d = Pointer<Utf8> Function(int);
KsStrError_d? _pfnKsStrError;

Pointer<Utf8> KsStrError(int code) {
  _pfnKsStrError ??= _keystone
      ?.lookupFunction<KsStrError_t, KsStrError_d>(_exportMap!['ks_strerror']!);
  return _pfnKsStrError!(code);
}

typedef KsErrno_t = Uint32 Function(IntPtr);
typedef KsErrno_d = int Function(int);
KsErrno_d? _pfnKsErrno;

int KsErrno(int engine) {
  _pfnKsErrno ??=
      _keystone?.lookupFunction<KsErrno_t, KsErrno_d>(_exportMap!['ks_errno']!);
  return _pfnKsErrno!(engine);
}

typedef KsArchSupported_t = Uint32 Function(Uint32 architecture);
typedef KsArchSupported_d = int Function(int architecture);
KsArchSupported_d? _pfnKsArchSupported;

bool KsArchSupported(int architecture) {
  _pfnKsArchSupported ??=
      _keystone?.lookupFunction<KsArchSupported_t, KsArchSupported_d>(
          _exportMap!['ks_arch_supported']!);
  return _pfnKsArchSupported!(architecture) == 1;
}

typedef KsOption_t = Uint32 Function(IntPtr, Int32, IntPtr);
typedef KsOption_d = int Function(int, int, int);
KsOption_d? _pfnKsOption;

int KsOption(int engine, int type, int value) {
  _pfnKsOption ??= _keystone
      ?.lookupFunction<KsOption_t, KsOption_d>(_exportMap!['ks_option']!);
  return _pfnKsOption!(engine, type, value);
}

typedef KsAsm_t = Uint32 Function(IntPtr, Pointer<Utf8>, Uint64,
    Pointer<IntPtr>, Pointer<IntPtr>, Pointer<IntPtr>);
typedef KsAsm_d = int Function(
    int, Pointer<Utf8>, int, Pointer<IntPtr>, Pointer<IntPtr>, Pointer<IntPtr>);
KsAsm_d? _pfnKsAsm;

int KsAsm(
    int engine,
    Pointer<Utf8> code,
    int baseAddress,
    Pointer<IntPtr> encoding,
    Pointer<IntPtr> size,
    Pointer<IntPtr> statements) {
  _pfnKsAsm ??=
      _keystone?.lookupFunction<KsAsm_t, KsAsm_d>(_exportMap!['ks_asm']!);
  return _pfnKsAsm!(engine, code, baseAddress, encoding, size, statements);
}
