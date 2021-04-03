import 'package:test/test.dart';

import 'bindings_test.dart' as bindings;
import 'operands_test.dart' as operands;
import 'asmbuilderbase_test.dart' as asmbuilderbase;
import 'asmbuilderintel_test.dart' as asmbuilderintel;
import 'keystone_test.dart' as keystone;

void main() {
  group('Binding tests', bindings.main);
  group('Operand classes tests', operands.main);
  group('AsmBuilderBase class tests', asmbuilderbase.main);
  group('AsmBuilderIntel classes tests', asmbuilderintel.main);
  group('Keystone class tests', keystone.main);
}
