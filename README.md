# keystone_dart

A keystone binding written in dart.

It also include a set of classes to help building assembler code and reduce syntax errors (Only Intel syntax implemented yet for builder (29-03-2021)).

## Examples

* Assemble raw assembler code
```dart
var code = 'push rax; mov rax, 1; pop rax;';
var res = engine.assembleRaw(code);
```

* Assemble built assembler code
```dart
// push rax
engine.builder!.push(intel.rax);
// mov rax, 1
engine.builder!.mov(intel.rax, intel.imm(1));
// pop rax
engine.builder!.pop(intel.rax);
var res = engine.assemble();
```

* Minimal sample
```dart
void main() {
  // setup library path (must have ending slash)
  ks.keystonePath = '../dependencies/keystone/x64/';

  ks.Keystone? engine;

  try {
    // Start Keystone engine
    engine = ks.Keystone(ks.KS_ARCH_X86, ks.KS_MODE_64);

    // Set Intel syntax
    engine.setOption(ks.KS_OPT_SYNTAX, ks.KS_OPT_SYNTAX_INTEL);

    // The assembler code string to be assembled
    var code = 'push rax; mov rax, 1; pop rax;';

    // Assemble using Keystone engine
    var res = engine.assembleRaw(code);

    // Print assembled code bytes
    var bytes = res.assembly.map((byte) => byte.toRadixString(16)).join(' ');
    print('assembly for $code -> $bytes');

  } on ks.KeystoneException catch (e) {
    print('Error $e');
  } finally {
    // release resources owned by the Keystone engine
    engine?.dispose();
  }
}
```

See `example/keystone_dart_example.dart` for a complete example.

## Prerequisites

Download precompiled Keystone binaries (https://www.keystone-engine.org/download/) or build from source (https://github.com/keystone-engine/keystone).

If the keystone engine compiled binary is not located in a default search folder for your operating system you must provide the path through `ks.keystonePath` variable (must have ending slash).

## TODO

* Complete asm builder helper function with more asm instructions (Intel)
* Add tests
* Add more syntax/architecture asm builder helpers