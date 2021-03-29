// Keystone API version
import 'dart:ffi';

import 'package:ffi/ffi.dart';

const int KS_API_MAJOR = 0;
const int KS_API_MINOR = 9;

// Package version
const int KS_VERSION_MAJOR = KS_API_MAJOR;
const int KS_VERSION_MINOR = KS_API_MINOR;
const int KS_VERSION_EXTRA = 2;

int ksMakeVersion(int major, int minor) => ((major << 8) + minor);

// Architecture type

const int KS_ARCH_ARM       = 1;                // ARM architecture (including Thumb, Thumb-2)
const int KS_ARCH_ARM64     = 2;                // ARM-64, also called AArch64
const int KS_ARCH_MIPS      = 3;                // Mips architecture
const int KS_ARCH_X86       = 4;                // X86 architecture (including x86 & x86-64)
const int KS_ARCH_PPC       = 5;                // PowerPC architecture (currently unsupported)
const int KS_ARCH_SPARC     = 6;                // Sparc architecture
const int KS_ARCH_SYSTEMZ   = 7;                // SystemZ architecture (S390X)
const int KS_ARCH_HEXAGON   = 8;                // Hexagon architecture
const int KS_ARCH_EVM       = 9;                // Ethereum Virtual Machine architecture

// Mode type

const int KS_MODE_LITTLE_ENDIAN = 0;            // little-endian mode (default mode)
const int KS_MODE_BIG_ENDIAN    = 1 << 30;      // big-endian mode

// arm / arm64
const int KS_MODE_ARM           = 1 << 0;       // ARM mode
const int KS_MODE_THUMB         = 1 << 4;       // THUMB mode (including Thumb-2)
const int KS_MODE_V8            = 1 << 6;       // ARMv8 A32 encodings for ARM

// mips
const int KS_MODE_MICRO         = 1 << 4;       // MicroMips mode
const int KS_MODE_MIPS3         = 1 << 5;       // Mips III ISA
const int KS_MODE_MIPS32R6      = 1 << 6;       // Mips32r6 ISA
const int KS_MODE_MIPS32        = 1 << 2;       // Mips32 ISA
const int KS_MODE_MIPS64        = 1 << 3;       // Mips64 ISA

// x86 / x64
const int KS_MODE_16            = 1 << 1;       // 16-bit mode
const int KS_MODE_32            = 1 << 2;       // 32-bit mode
const int KS_MODE_64            = 1 << 3;       // 64-bit mode

// ppc 
const int KS_MODE_PPC32         = 1 << 2;       // 32-bit mode
const int KS_MODE_PPC64         = 1 << 3;       // 64-bit mode
const int KS_MODE_QPX           = 1 << 4;       // Quad Processing eXtensions mode

// sparc
const int KS_MODE_SPARC32       = 1 << 2;       // 32-bit mode
const int KS_MODE_SPARC64       = 1 << 3;       // 64-bit mode
const int KS_MODE_V9            = 1 << 4;       // SparcV9 mode

// All generic errors related to input assembly >= KS_ERR_ASM
const int KS_ERR_ASM            = 128;

// All architecture-specific errors related to input assembly >= KS_ERR_ASM_ARCH
const int KS_ERR_ASM_ARCH       = 512;

// All type of errors encountered by Keystone API.

const int KS_ERR_OK = 0;
const int KS_ERR_NOMEM = 1;
const int KS_ERR_ARCH = 2;
const int KS_ERR_HANDLE = 3;
const int KS_ERR_MODE = 4;
const int KS_ERR_VERSION = 5;
const int KS_ERR_OPT_INVALID = 6;
const int KS_ERR_ASM_EXPR_TOKEN = 128;
const int KS_ERR_ASM_DIRECTIVE_VALUE_RANGE = 129;
const int KS_ERR_ASM_DIRECTIVE_ID = 130;
const int KS_ERR_ASM_DIRECTIVE_TOKEN = 131;
const int KS_ERR_ASM_DIRECTIVE_STR = 132;
const int KS_ERR_ASM_DIRECTIVE_COMMA = 133;
const int KS_ERR_ASM_DIRECTIVE_RELOC_NAME = 134;
const int KS_ERR_ASM_DIRECTIVE_RELOC_TOKEN = 135;
const int KS_ERR_ASM_DIRECTIVE_FPOINT = 136;
const int KS_ERR_ASM_DIRECTIVE_UNKNOWN = 137;
const int KS_ERR_ASM_DIRECTIVE_EQU = 138;
const int KS_ERR_ASM_DIRECTIVE_INVALID = 139;
const int KS_ERR_ASM_VARIANT_INVALID = 140;
const int KS_ERR_ASM_EXPR_BRACKET = 141;
const int KS_ERR_ASM_SYMBOL_MODIFIER = 142;
const int KS_ERR_ASM_SYMBOL_REDEFINED = 143;
const int KS_ERR_ASM_SYMBOL_MISSING = 144;
const int KS_ERR_ASM_RPAREN = 145;
const int KS_ERR_ASM_STAT_TOKEN = 146;
const int KS_ERR_ASM_UNSUPPORTED = 147;
const int KS_ERR_ASM_MACRO_TOKEN = 148;
const int KS_ERR_ASM_MACRO_PAREN = 149;
const int KS_ERR_ASM_MACRO_EQU = 150;
const int KS_ERR_ASM_MACRO_ARGS = 151;
const int KS_ERR_ASM_MACRO_LEVELS_EXCEED = 152;
const int KS_ERR_ASM_MACRO_STR = 153;
const int KS_ERR_ASM_MACRO_INVALID = 154;
const int KS_ERR_ASM_ESC_BACKSLASH = 155;
const int KS_ERR_ASM_ESC_OCTAL = 156;
const int KS_ERR_ASM_ESC_SEQUENCE = 157;
const int KS_ERR_ASM_ESC_STR = 158;
const int KS_ERR_ASM_TOKEN_INVALID = 159;
const int KS_ERR_ASM_INSN_UNSUPPORTED = 160;
const int KS_ERR_ASM_FIXUP_INVALID = 161;
const int KS_ERR_ASM_LABEL_INVALID = 162;
const int KS_ERR_ASM_FRAGMENT_INVALID = 163;
const int KS_ERR_ASM_INVALIDOPERAND = 512;
const int KS_ERR_ASM_MISSINGFEATURE = 513;
const int KS_ERR_ASM_MNEMONICFAIL = 514;

// Resolver callback to provide value for a missing symbol in @symbol.
// To handle a symbol, the resolver must put value of the symbol in @value,
// then returns True.
// If we do not resolve a missing symbol, this function must return False.
// In that case, ks_asm() would eventually return with error KS_ERR_ASM_SYMBOL_MISSING.

// To register the resolver, pass its function address to ks_option(), using
// option KS_OPT_SYM_RESOLVER. For example, see samples/sample.c.
typedef KsSymResolver_t = Uint32 Function(Pointer<Utf8>, Pointer<Uint64>);

// Runtime option for the Keystone engine
const int KS_OPT_SYNTAX       = 1;    // Choose syntax for input assembly
const int KS_OPT_SYM_RESOLVER = 2;    // Set symbol resolver callback


// Runtime option value (associated with ks_opt_type above)

const int KS_OPT_SYNTAX_INTEL   =   1 << 0; // X86 Intel syntax - default on X86 (KS_OPT_SYNTAX).
const int KS_OPT_SYNTAX_ATT     =   1 << 1; // X86 ATT asm syntax (KS_OPT_SYNTAX).
const int KS_OPT_SYNTAX_NASM    =   1 << 2; // X86 Nasm syntax (KS_OPT_SYNTAX).
const int KS_OPT_SYNTAX_MASM    =   1 << 3; // X86 Masm syntax (KS_OPT_SYNTAX) - unsupported yet.
const int KS_OPT_SYNTAX_GAS     =   1 << 4; // X86 GNU GAS syntax (KS_OPT_SYNTAX).
const int KS_OPT_SYNTAX_RADIX16 =   1 << 5; // All immediates are in hex format (i.e 12 is 0x12)
