.text
.globl _start
_start:
 mov 4(%esp), %eax
 imul $3, %eax
 add 8(%esp), %eax
 ret
.fill 4096,1,0x90
.data
.globl _payload
_payload:
.fill 33554432,1,0x41
