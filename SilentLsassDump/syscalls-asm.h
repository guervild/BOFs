#pragma once
#include "Syscalls.h"

#define ZwtTEBAsm64 GetTEBAsm64
__asm__("GetTEBAsm64: \n\
	push rbx \n\
    xor rbx, rbx \n\
    xor rax, rax \n\
    mov rbx, qword ptr gs:[0x30] \n\
	mov rax, rbx \n\
	pop rbx \n\
	ret \n\
");

#define ZwAdjustPrivilegesToken NtAdjustPrivilegesToken
__asm__("NtAdjustPrivilegesToken: \n\
	mov rax, gs:[0x60]                                  \n\
NtAdjustPrivilegesToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042 \n\
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x003e \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x003f \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0040 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0041 \n\
	jmp NtAdjustPrivilegesToken_Epilogue \n\
NtAdjustPrivilegesToken_SystemCall_Unknown:            \n\
	ret \n\
NtAdjustPrivilegesToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwClose NtClose
__asm__("NtClose: \n\
	mov rax, gs:[0x60]                  \n\
NtClose_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtClose_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtClose_Check_10_0_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtClose_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtClose_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtClose_SystemCall_6_3_XXXX \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtClose_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtClose_SystemCall_6_1_7601 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtClose_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtClose_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtClose_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtClose_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtClose_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtClose_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtClose_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtClose_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtClose_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtClose_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtClose_SystemCall_10_0_19042 \n\
	jmp NtClose_SystemCall_Unknown \n\
NtClose_SystemCall_6_1_7600:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_1_7601:           \n\
	mov eax, 0x000c \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x000d \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x000e \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10240:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_10586:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_14393:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_15063:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_16299:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17134:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_17763:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18362:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_18363:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19041:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_10_0_19042:         \n\
	mov eax, 0x000f \n\
	jmp NtClose_Epilogue \n\
NtClose_SystemCall_Unknown:            \n\
	ret \n\
NtClose_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateKey NtCreateKey
__asm__("NtCreateKey: \n\
	mov rax, gs:[0x60]                      \n\
NtCreateKey_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateKey_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateKey_Check_10_0_XXXX \n\
	jmp NtCreateKey_SystemCall_Unknown \n\
NtCreateKey_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateKey_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateKey_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateKey_SystemCall_6_3_XXXX \n\
	jmp NtCreateKey_SystemCall_Unknown \n\
NtCreateKey_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateKey_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateKey_SystemCall_6_1_7601 \n\
	jmp NtCreateKey_SystemCall_Unknown \n\
NtCreateKey_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateKey_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateKey_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateKey_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateKey_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateKey_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateKey_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateKey_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateKey_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateKey_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateKey_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateKey_SystemCall_10_0_19042 \n\
	jmp NtCreateKey_SystemCall_Unknown \n\
NtCreateKey_SystemCall_6_1_7600:           \n\
	mov eax, 0x001a \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_6_1_7601:           \n\
	mov eax, 0x001a \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x001b \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x001c \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_10240:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_10586:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_14393:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_15063:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_16299:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_17134:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_17763:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_18362:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_18363:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_19041:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_10_0_19042:         \n\
	mov eax, 0x001d \n\
	jmp NtCreateKey_Epilogue \n\
NtCreateKey_SystemCall_Unknown:            \n\
	ret \n\
NtCreateKey_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwCreateThreadEx NtCreateThreadEx
__asm__("NtCreateThreadEx: \n\
	mov rax, gs:[0x60]                           \n\
NtCreateThreadEx_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtCreateThreadEx_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtCreateThreadEx_Check_10_0_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtCreateThreadEx_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtCreateThreadEx_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtCreateThreadEx_SystemCall_6_3_XXXX \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtCreateThreadEx_SystemCall_6_1_7601 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtCreateThreadEx_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtCreateThreadEx_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtCreateThreadEx_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtCreateThreadEx_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtCreateThreadEx_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtCreateThreadEx_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtCreateThreadEx_SystemCall_10_0_19042 \n\
	jmp NtCreateThreadEx_SystemCall_Unknown \n\
NtCreateThreadEx_SystemCall_6_1_7600:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_1_7601:           \n\
	mov eax, 0x00a5 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00af \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00b0 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10240:         \n\
	mov eax, 0x00b3 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_10586:         \n\
	mov eax, 0x00b4 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_14393:         \n\
	mov eax, 0x00b6 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_15063:         \n\
	mov eax, 0x00b9 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_16299:         \n\
	mov eax, 0x00ba \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17134:         \n\
	mov eax, 0x00bb \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_17763:         \n\
	mov eax, 0x00bc \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18362:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_18363:         \n\
	mov eax, 0x00bd \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19041:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_10_0_19042:         \n\
	mov eax, 0x00c1 \n\
	jmp NtCreateThreadEx_Epilogue \n\
NtCreateThreadEx_SystemCall_Unknown:            \n\
	ret \n\
NtCreateThreadEx_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwDeleteKey NtDeleteKey
__asm__("NtDeleteKey: \n\
	mov rax, gs:[0x60]                      \n\
NtDeleteKey_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtDeleteKey_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtDeleteKey_Check_10_0_XXXX \n\
	jmp NtDeleteKey_SystemCall_Unknown \n\
NtDeleteKey_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtDeleteKey_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtDeleteKey_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtDeleteKey_SystemCall_6_3_XXXX \n\
	jmp NtDeleteKey_SystemCall_Unknown \n\
NtDeleteKey_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtDeleteKey_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtDeleteKey_SystemCall_6_1_7601 \n\
	jmp NtDeleteKey_SystemCall_Unknown \n\
NtDeleteKey_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtDeleteKey_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtDeleteKey_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtDeleteKey_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtDeleteKey_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtDeleteKey_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtDeleteKey_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtDeleteKey_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtDeleteKey_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtDeleteKey_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtDeleteKey_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtDeleteKey_SystemCall_10_0_19042 \n\
	jmp NtDeleteKey_SystemCall_Unknown \n\
NtDeleteKey_SystemCall_6_1_7600:           \n\
	mov eax, 0x00b3 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_6_1_7601:           \n\
	mov eax, 0x00b3 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x00c0 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x00c2 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_10240:         \n\
	mov eax, 0x00c5 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_10586:         \n\
	mov eax, 0x00c6 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_14393:         \n\
	mov eax, 0x00c8 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_15063:         \n\
	mov eax, 0x00cb \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_16299:         \n\
	mov eax, 0x00cc \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_17134:         \n\
	mov eax, 0x00cd \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_17763:         \n\
	mov eax, 0x00ce \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_18362:         \n\
	mov eax, 0x00cf \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_18363:         \n\
	mov eax, 0x00cf \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_19041:         \n\
	mov eax, 0x00d3 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_10_0_19042:         \n\
	mov eax, 0x00d3 \n\
	jmp NtDeleteKey_Epilogue \n\
NtDeleteKey_SystemCall_Unknown:            \n\
	ret \n\
NtDeleteKey_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenKey NtOpenKey
__asm__("NtOpenKey: \n\
	mov rax, gs:[0x60]                    \n\
NtOpenKey_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenKey_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenKey_Check_10_0_XXXX \n\
	jmp NtOpenKey_SystemCall_Unknown \n\
NtOpenKey_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenKey_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenKey_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenKey_SystemCall_6_3_XXXX \n\
	jmp NtOpenKey_SystemCall_Unknown \n\
NtOpenKey_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenKey_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenKey_SystemCall_6_1_7601 \n\
	jmp NtOpenKey_SystemCall_Unknown \n\
NtOpenKey_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenKey_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenKey_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenKey_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenKey_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenKey_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenKey_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenKey_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenKey_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenKey_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenKey_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenKey_SystemCall_10_0_19042 \n\
	jmp NtOpenKey_SystemCall_Unknown \n\
NtOpenKey_SystemCall_6_1_7600:           \n\
	mov eax, 0x000f \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_6_1_7601:           \n\
	mov eax, 0x000f \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0010 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0011 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_10240:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_10586:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_14393:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_15063:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_16299:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_17134:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_17763:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_18362:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_18363:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_19041:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_10_0_19042:         \n\
	mov eax, 0x0012 \n\
	jmp NtOpenKey_Epilogue \n\
NtOpenKey_SystemCall_Unknown:            \n\
	ret \n\
NtOpenKey_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcess NtOpenProcess
__asm__("NtOpenProcess: \n\
	mov rax, gs:[0x60]                        \n\
NtOpenProcess_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcess_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcess_Check_10_0_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcess_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcess_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcess_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcess_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcess_SystemCall_6_1_7601 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcess_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcess_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcess_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcess_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcess_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcess_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcess_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcess_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcess_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcess_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcess_SystemCall_10_0_19042 \n\
	jmp NtOpenProcess_SystemCall_Unknown \n\
NtOpenProcess_SystemCall_6_1_7600:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_1_7601:           \n\
	mov eax, 0x0023 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x0024 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x0025 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10240:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_10586:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_14393:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_15063:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_16299:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17134:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_17763:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18362:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_18363:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19041:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_10_0_19042:         \n\
	mov eax, 0x0026 \n\
	jmp NtOpenProcess_Epilogue \n\
NtOpenProcess_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcess_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwOpenProcessToken NtOpenProcessToken
__asm__("NtOpenProcessToken: \n\
	mov rax, gs:[0x60]                             \n\
NtOpenProcessToken_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtOpenProcessToken_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtOpenProcessToken_Check_10_0_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtOpenProcessToken_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtOpenProcessToken_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtOpenProcessToken_SystemCall_6_3_XXXX \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtOpenProcessToken_SystemCall_6_1_7601 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtOpenProcessToken_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtOpenProcessToken_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtOpenProcessToken_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtOpenProcessToken_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtOpenProcessToken_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtOpenProcessToken_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtOpenProcessToken_SystemCall_10_0_19042 \n\
	jmp NtOpenProcessToken_SystemCall_Unknown \n\
NtOpenProcessToken_SystemCall_6_1_7600:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_1_7601:           \n\
	mov eax, 0x00f9 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x010b \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x010e \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10240:         \n\
	mov eax, 0x0114 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_10586:         \n\
	mov eax, 0x0117 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_14393:         \n\
	mov eax, 0x0119 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_15063:         \n\
	mov eax, 0x011d \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_16299:         \n\
	mov eax, 0x011f \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17134:         \n\
	mov eax, 0x0121 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_17763:         \n\
	mov eax, 0x0122 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18362:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_18363:         \n\
	mov eax, 0x0123 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19041:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_10_0_19042:         \n\
	mov eax, 0x0128 \n\
	jmp NtOpenProcessToken_Epilogue \n\
NtOpenProcessToken_SystemCall_Unknown:            \n\
	ret \n\
NtOpenProcessToken_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

#define ZwSetValueKey NtSetValueKey
__asm__("NtSetValueKey: \n\
	mov rax, gs:[0x60]                        \n\
NtSetValueKey_Check_X_X_XXXX:                \n\
	cmp dword ptr [rax+0x118], 6 \n\
	je  NtSetValueKey_Check_6_X_XXXX \n\
	cmp dword ptr [rax+0x118], 10 \n\
	je  NtSetValueKey_Check_10_0_XXXX \n\
	jmp NtSetValueKey_SystemCall_Unknown \n\
NtSetValueKey_Check_6_X_XXXX:                \n\
	cmp dword ptr [rax+0x11c], 1 \n\
	je  NtSetValueKey_Check_6_1_XXXX \n\
	cmp dword ptr [rax+0x11c], 2 \n\
	je  NtSetValueKey_SystemCall_6_2_XXXX \n\
	cmp dword ptr [rax+0x11c], 3 \n\
	je  NtSetValueKey_SystemCall_6_3_XXXX \n\
	jmp NtSetValueKey_SystemCall_Unknown \n\
NtSetValueKey_Check_6_1_XXXX:                \n\
	cmp word ptr [rax+0x120], 7600 \n\
	je  NtSetValueKey_SystemCall_6_1_7600 \n\
	cmp word ptr [rax+0x120], 7601 \n\
	je  NtSetValueKey_SystemCall_6_1_7601 \n\
	jmp NtSetValueKey_SystemCall_Unknown \n\
NtSetValueKey_Check_10_0_XXXX:               \n\
	cmp word ptr [rax+0x120], 10240 \n\
	je  NtSetValueKey_SystemCall_10_0_10240 \n\
	cmp word ptr [rax+0x120], 10586 \n\
	je  NtSetValueKey_SystemCall_10_0_10586 \n\
	cmp word ptr [rax+0x120], 14393 \n\
	je  NtSetValueKey_SystemCall_10_0_14393 \n\
	cmp word ptr [rax+0x120], 15063 \n\
	je  NtSetValueKey_SystemCall_10_0_15063 \n\
	cmp word ptr [rax+0x120], 16299 \n\
	je  NtSetValueKey_SystemCall_10_0_16299 \n\
	cmp word ptr [rax+0x120], 17134 \n\
	je  NtSetValueKey_SystemCall_10_0_17134 \n\
	cmp word ptr [rax+0x120], 17763 \n\
	je  NtSetValueKey_SystemCall_10_0_17763 \n\
	cmp word ptr [rax+0x120], 18362 \n\
	je  NtSetValueKey_SystemCall_10_0_18362 \n\
	cmp word ptr [rax+0x120], 18363 \n\
	je  NtSetValueKey_SystemCall_10_0_18363 \n\
	cmp word ptr [rax+0x120], 19041 \n\
	je  NtSetValueKey_SystemCall_10_0_19041 \n\
	cmp word ptr [rax+0x120], 19042 \n\
	je  NtSetValueKey_SystemCall_10_0_19042 \n\
	jmp NtSetValueKey_SystemCall_Unknown \n\
NtSetValueKey_SystemCall_6_1_7600:           \n\
	mov eax, 0x005d \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_6_1_7601:           \n\
	mov eax, 0x005d \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_6_2_XXXX:           \n\
	mov eax, 0x005e \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_6_3_XXXX:           \n\
	mov eax, 0x005f \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_10240:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_10586:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_14393:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_15063:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_16299:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_17134:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_17763:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_18362:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_18363:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_19041:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_10_0_19042:         \n\
	mov eax, 0x0060 \n\
	jmp NtSetValueKey_Epilogue \n\
NtSetValueKey_SystemCall_Unknown:            \n\
	ret \n\
NtSetValueKey_Epilogue: \n\
	mov r10, rcx \n\
	syscall \n\
	ret \n\
");

