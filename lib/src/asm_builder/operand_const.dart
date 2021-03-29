import 'operand.dart';

const rax = RegisterOperand('rax');
const rbx = RegisterOperand('rbx');
const rcx = RegisterOperand('rcx');
const rdx = RegisterOperand('rdx');
const rbp = RegisterOperand('rbp');
const rsp = RegisterOperand('rsp');
const rsi = RegisterOperand('rsi');
const rdi = RegisterOperand('rdi');
const r8 = RegisterOperand('r8');
const r9 = RegisterOperand('r9');
const r10 = RegisterOperand('r10');
const r11 = RegisterOperand('r11');
const r12 = RegisterOperand('r12');
const r13 = RegisterOperand('r13');
const r14 = RegisterOperand('r14');
const r15 = RegisterOperand('r15');
const rip = RegisterOperand('rip');

ImmediateValueOperand imm(int value) => ImmediateValueOperand(value);