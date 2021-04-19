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
// get assembly builder
var a = intel.AsmBuilderIntel64();

// push rax
a.push(a.rax);
// mov rax, 1
a.mov(a.rax, a.imm(1));
// pop rax
a.pop(a.rax);

// assemble code
var res = engine.assemble(a);
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

Add you own asm helper by extending `AsmBuilderBase` class. The package comes with a basic intel syntax helper.

## Prerequisites

Download precompiled Keystone binaries (https://www.keystone-engine.org/download/) or build from source (https://github.com/keystone-engine/keystone).

If the keystone engine compiled binary is not located in a default search folder for your operating system you must provide the path through `ks.keystonePath` variable (must have ending slash).

## Todos

* Embed windows/linux/macos keystone shared library in package and remove `keystonePath` global variable if possible
* Add more tests
* Expand current Intel assembler assembler helper
* Add more syntax/architecture asm builder helpers