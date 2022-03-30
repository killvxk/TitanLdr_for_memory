;;
;; Reflective Loader
;;
;; GuidePoint Security LLC
;;
;; Threat and Attack Simulation
;;
[BITS 64]

;;
;; Export
;;
GLOBAL GetIp
GLOBAL Hooks
GLOBAL BeaconConfig
GLOBAL AllocAddress
GLOBAL PEAddress
GLOBAL dwPE
[SECTION .text$C]

Hooks:
	;;
	;; Arbitrary symbol to reference as
	;; start of hook pages
	;;
	nop

[SECTION .text$F]
AllocAddress:
	push rbp
	mov rbp, rsp
	mov rax, 04242424242424242h
	pop rbp 
	retn
BeaconConfig:
	push rbp
	mov rbp, rsp
	mov rax, 04141414141414141h
	pop rbp 
	retn
PEAddress:
	push rbp
	mov rbp, rsp
	mov rax, 04343434343434343h
	pop rbp 
	retn
dwPE:
	push rbp
	mov rbp, rsp
	mov rax, 04545454545454545h
	pop rbp 
	retn
GetIp:
	;;
	;; Execute next instruction
	;; 
	call	get_ret_ptr

get_ret_ptr:
	;;
	;; Pop address and sub diff
	;;
	pop	rax
	sub	rax, 5
	ret


Leave:
	db 'E', 'N', 'D', 'O', 'F', 'C', 'O', 'D', 'E'
