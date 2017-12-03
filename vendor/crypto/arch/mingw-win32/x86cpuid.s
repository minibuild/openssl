.file	"x86cpuid.s"
.text
.globl	_OPENSSL_ia32_cpuid
.def	_OPENSSL_ia32_cpuid;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_cpuid:
.L_OPENSSL_ia32_cpuid_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	xorl	%edx,%edx
	pushfl
	popl	%eax
	movl	%eax,%ecx
	xorl	$2097152,%eax
	pushl	%eax
	popfl
	pushfl
	popl	%eax
	xorl	%eax,%ecx
	xorl	%eax,%eax
	movl	20(%esp),%esi
	movl	%eax,8(%esi)
	btl	$21,%ecx
	jnc	.L000nocpuid
	.byte	0x0f,0xa2
	movl	%eax,%edi
	xorl	%eax,%eax
	cmpl	$1970169159,%ebx
	setne	%al
	movl	%eax,%ebp
	cmpl	$1231384169,%edx
	setne	%al
	orl	%eax,%ebp
	cmpl	$1818588270,%ecx
	setne	%al
	orl	%eax,%ebp
	jz	.L001intel
	cmpl	$1752462657,%ebx
	setne	%al
	movl	%eax,%esi
	cmpl	$1769238117,%edx
	setne	%al
	orl	%eax,%esi
	cmpl	$1145913699,%ecx
	setne	%al
	orl	%eax,%esi
	jnz	.L001intel
	movl	$2147483648,%eax
	.byte	0x0f,0xa2
	cmpl	$2147483649,%eax
	jb	.L001intel
	movl	%eax,%esi
	movl	$2147483649,%eax
	.byte	0x0f,0xa2
	orl	%ecx,%ebp
	andl	$2049,%ebp
	cmpl	$2147483656,%esi
	jb	.L001intel
	movl	$2147483656,%eax
	.byte	0x0f,0xa2
	movzbl	%cl,%esi
	incl	%esi
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	btl	$28,%edx
	jnc	.L002generic
	shrl	$16,%ebx
	andl	$255,%ebx
	cmpl	%esi,%ebx
	ja	.L002generic
	andl	$4026531839,%edx
	jmp	.L002generic
.L001intel:
	cmpl	$4,%edi
	movl	$-1,%esi
	jb	.L003nocacheinfo
	movl	$4,%eax
	movl	$0,%ecx
	.byte	0x0f,0xa2
	movl	%eax,%esi
	shrl	$14,%esi
	andl	$4095,%esi
.L003nocacheinfo:
	movl	$1,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	andl	$3220176895,%edx
	cmpl	$0,%ebp
	jne	.L004notintel
	orl	$1073741824,%edx
	andb	$15,%ah
	cmpb	$15,%ah
	jne	.L004notintel
	orl	$1048576,%edx
.L004notintel:
	btl	$28,%edx
	jnc	.L002generic
	andl	$4026531839,%edx
	cmpl	$0,%esi
	je	.L002generic
	orl	$268435456,%edx
	shrl	$16,%ebx
	cmpb	$1,%bl
	ja	.L002generic
	andl	$4026531839,%edx
.L002generic:
	andl	$2048,%ebp
	andl	$4294965247,%ecx
	movl	%edx,%esi
	orl	%ecx,%ebp
	cmpl	$7,%edi
	movl	20(%esp),%edi
	jb	.L005no_extended_info
	movl	$7,%eax
	xorl	%ecx,%ecx
	.byte	0x0f,0xa2
	movl	%ebx,8(%edi)
.L005no_extended_info:
	btl	$27,%ebp
	jnc	.L006clear_avx
	xorl	%ecx,%ecx
.byte	15,1,208
	andl	$6,%eax
	cmpl	$6,%eax
	je	.L007done
	cmpl	$2,%eax
	je	.L006clear_avx
.L008clear_xmm:
	andl	$4261412861,%ebp
	andl	$4278190079,%esi
.L006clear_avx:
	andl	$4026525695,%ebp
	andl	$4294967263,8(%edi)
.L007done:
	movl	%esi,%eax
	movl	%ebp,%edx
.L000nocpuid:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_rdtsc
.def	_OPENSSL_rdtsc;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_rdtsc:
.L_OPENSSL_rdtsc_begin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	leal	_OPENSSL_ia32cap_P,%ecx
	btl	$4,(%ecx)
	jnc	.L009notsc
	.byte	0x0f,0x31
.L009notsc:
	ret
.globl	_OPENSSL_instrument_halt
.def	_OPENSSL_instrument_halt;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_halt:
.L_OPENSSL_instrument_halt_begin:
	leal	_OPENSSL_ia32cap_P,%ecx
	btl	$4,(%ecx)
	jnc	.L010nohalt
.long	2421723150
	andl	$3,%eax
	jnz	.L010nohalt
	pushfl
	popl	%eax
	btl	$9,%eax
	jnc	.L010nohalt
	.byte	0x0f,0x31
	pushl	%edx
	pushl	%eax
	hlt
	.byte	0x0f,0x31
	subl	(%esp),%eax
	sbbl	4(%esp),%edx
	addl	$8,%esp
	ret
.L010nohalt:
	xorl	%eax,%eax
	xorl	%edx,%edx
	ret
.globl	_OPENSSL_far_spin
.def	_OPENSSL_far_spin;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_far_spin:
.L_OPENSSL_far_spin_begin:
	pushfl
	popl	%eax
	btl	$9,%eax
	jnc	.L011nospin
	movl	4(%esp),%eax
	movl	8(%esp),%ecx
.long	2430111262
	xorl	%eax,%eax
	movl	(%ecx),%edx
	jmp	.L012spin
.align	16
.L012spin:
	incl	%eax
	cmpl	(%ecx),%edx
	je	.L012spin
.long	529567888
	ret
.L011nospin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	ret
.globl	_OPENSSL_wipe_cpu
.def	_OPENSSL_wipe_cpu;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_wipe_cpu:
.L_OPENSSL_wipe_cpu_begin:
	xorl	%eax,%eax
	xorl	%edx,%edx
	leal	_OPENSSL_ia32cap_P,%ecx
	movl	(%ecx),%ecx
	btl	$1,(%ecx)
	jnc	.L013no_x87
	andl	$83886080,%ecx
	cmpl	$83886080,%ecx
	jne	.L014no_sse2
	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
.L014no_sse2:
.long	4007259865,4007259865,4007259865,4007259865,2430851995
.L013no_x87:
	leal	4(%esp),%eax
	ret
.globl	_OPENSSL_atomic_add
.def	_OPENSSL_atomic_add;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_atomic_add:
.L_OPENSSL_atomic_add_begin:
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	pushl	%ebx
	nop
	movl	(%edx),%eax
.L015spin:
	leal	(%eax,%ecx,1),%ebx
	nop
.long	447811568
	jne	.L015spin
	movl	%ebx,%eax
	popl	%ebx
	ret
.globl	_OPENSSL_indirect_call
.def	_OPENSSL_indirect_call;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_indirect_call:
.L_OPENSSL_indirect_call_begin:
	pushl	%ebp
	movl	%esp,%ebp
	subl	$28,%esp
	movl	12(%ebp),%ecx
	movl	%ecx,(%esp)
	movl	16(%ebp),%edx
	movl	%edx,4(%esp)
	movl	20(%ebp),%eax
	movl	%eax,8(%esp)
	movl	24(%ebp),%eax
	movl	%eax,12(%esp)
	movl	28(%ebp),%eax
	movl	%eax,16(%esp)
	movl	32(%ebp),%eax
	movl	%eax,20(%esp)
	movl	36(%ebp),%eax
	movl	%eax,24(%esp)
	call	*8(%ebp)
	movl	%ebp,%esp
	popl	%ebp
	ret
.globl	_OPENSSL_cleanse
.def	_OPENSSL_cleanse;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_cleanse:
.L_OPENSSL_cleanse_begin:
	movl	4(%esp),%edx
	movl	8(%esp),%ecx
	xorl	%eax,%eax
	cmpl	$7,%ecx
	jae	.L016lot
	cmpl	$0,%ecx
	je	.L017ret
.L018little:
	movb	%al,(%edx)
	subl	$1,%ecx
	leal	1(%edx),%edx
	jnz	.L018little
.L017ret:
	ret
.align	16
.L016lot:
	testl	$3,%edx
	jz	.L019aligned
	movb	%al,(%edx)
	leal	-1(%ecx),%ecx
	leal	1(%edx),%edx
	jmp	.L016lot
.L019aligned:
	movl	%eax,(%edx)
	leal	-4(%ecx),%ecx
	testl	$-4,%ecx
	leal	4(%edx),%edx
	jnz	.L019aligned
	cmpl	$0,%ecx
	jne	.L018little
	ret
.globl	_CRYPTO_memcmp
.def	_CRYPTO_memcmp;	.scl	2;	.type	32;	.endef
.align	16
_CRYPTO_memcmp:
.L_CRYPTO_memcmp_begin:
	pushl	%esi
	pushl	%edi
	movl	12(%esp),%esi
	movl	16(%esp),%edi
	movl	20(%esp),%ecx
	xorl	%eax,%eax
	xorl	%edx,%edx
	cmpl	$0,%ecx
	je	.L020no_data
.L021loop:
	movb	(%esi),%dl
	leal	1(%esi),%esi
	xorb	(%edi),%dl
	leal	1(%edi),%edi
	orb	%dl,%al
	decl	%ecx
	jnz	.L021loop
	negl	%eax
	shrl	$31,%eax
.L020no_data:
	popl	%edi
	popl	%esi
	ret
.globl	_OPENSSL_instrument_bus
.def	_OPENSSL_instrument_bus;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_bus:
.L_OPENSSL_instrument_bus_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	$0,%eax
	leal	_OPENSSL_ia32cap_P,%edx
	btl	$4,(%edx)
	jnc	.L022nogo
	btl	$19,(%edx)
	jnc	.L022nogo
	movl	20(%esp),%edi
	movl	24(%esp),%ecx
	.byte	0x0f,0x31
	movl	%eax,%esi
	movl	$0,%ebx
	clflush	(%edi)
.byte	240
	addl	%ebx,(%edi)
	jmp	.L023loop
.align	16
.L023loop:
	.byte	0x0f,0x31
	movl	%eax,%edx
	subl	%esi,%eax
	movl	%edx,%esi
	movl	%eax,%ebx
	clflush	(%edi)
.byte	240
	addl	%eax,(%edi)
	leal	4(%edi),%edi
	subl	$1,%ecx
	jnz	.L023loop
	movl	24(%esp),%eax
.L022nogo:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_instrument_bus2
.def	_OPENSSL_instrument_bus2;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_instrument_bus2:
.L_OPENSSL_instrument_bus2_begin:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	$0,%eax
	leal	_OPENSSL_ia32cap_P,%edx
	btl	$4,(%edx)
	jnc	.L024nogo
	btl	$19,(%edx)
	jnc	.L024nogo
	movl	20(%esp),%edi
	movl	24(%esp),%ecx
	movl	28(%esp),%ebp
	.byte	0x0f,0x31
	movl	%eax,%esi
	movl	$0,%ebx
	clflush	(%edi)
.byte	240
	addl	%ebx,(%edi)
	.byte	0x0f,0x31
	movl	%eax,%edx
	subl	%esi,%eax
	movl	%edx,%esi
	movl	%eax,%ebx
	jmp	.L025loop2
.align	16
.L025loop2:
	clflush	(%edi)
.byte	240
	addl	%eax,(%edi)
	subl	$1,%ebp
	jz	.L026done2
	.byte	0x0f,0x31
	movl	%eax,%edx
	subl	%esi,%eax
	movl	%edx,%esi
	cmpl	%ebx,%eax
	movl	%eax,%ebx
	movl	$0,%edx
	setne	%dl
	subl	%edx,%ecx
	leal	(%edi,%edx,4),%edi
	jnz	.L025loop2
.L026done2:
	movl	24(%esp),%eax
	subl	%ecx,%eax
.L024nogo:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.globl	_OPENSSL_ia32_rdrand
.def	_OPENSSL_ia32_rdrand;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_rdrand:
.L_OPENSSL_ia32_rdrand_begin:
	movl	$8,%ecx
.L027loop:
.byte	15,199,240
	jc	.L028break
	loop	.L027loop
.L028break:
	cmpl	$0,%eax
	cmovel	%ecx,%eax
	ret
.globl	_OPENSSL_ia32_rdrand_bytes
.def	_OPENSSL_ia32_rdrand_bytes;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_rdrand_bytes:
.L_OPENSSL_ia32_rdrand_bytes_begin:
	pushl	%edi
	pushl	%ebx
	xorl	%eax,%eax
	movl	12(%esp),%edi
	movl	16(%esp),%ebx
	cmpl	$0,%ebx
	je	.L029done
	movl	$8,%ecx
.L030loop:
.byte	15,199,242
	jc	.L031break
	loop	.L030loop
	jmp	.L029done
.align	16
.L031break:
	cmpl	$4,%ebx
	jb	.L032tail
	movl	%edx,(%edi)
	leal	4(%edi),%edi
	addl	$4,%eax
	subl	$4,%ebx
	jz	.L029done
	movl	$8,%ecx
	jmp	.L030loop
.align	16
.L032tail:
	movb	%dl,(%edi)
	leal	1(%edi),%edi
	incl	%eax
	shrl	$8,%edx
	decl	%ebx
	jnz	.L032tail
.L029done:
	popl	%ebx
	popl	%edi
	ret
.globl	_OPENSSL_ia32_rdseed
.def	_OPENSSL_ia32_rdseed;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_rdseed:
.L_OPENSSL_ia32_rdseed_begin:
	movl	$8,%ecx
.L033loop:
.byte	15,199,248
	jc	.L034break
	loop	.L033loop
.L034break:
	cmpl	$0,%eax
	cmovel	%ecx,%eax
	ret
.globl	_OPENSSL_ia32_rdseed_bytes
.def	_OPENSSL_ia32_rdseed_bytes;	.scl	2;	.type	32;	.endef
.align	16
_OPENSSL_ia32_rdseed_bytes:
.L_OPENSSL_ia32_rdseed_bytes_begin:
	pushl	%edi
	pushl	%ebx
	xorl	%eax,%eax
	movl	12(%esp),%edi
	movl	16(%esp),%ebx
	cmpl	$0,%ebx
	je	.L035done
	movl	$8,%ecx
.L036loop:
.byte	15,199,250
	jc	.L037break
	loop	.L036loop
	jmp	.L035done
.align	16
.L037break:
	cmpl	$4,%ebx
	jb	.L038tail
	movl	%edx,(%edi)
	leal	4(%edi),%edi
	addl	$4,%eax
	subl	$4,%ebx
	jz	.L035done
	movl	$8,%ecx
	jmp	.L036loop
.align	16
.L038tail:
	movb	%dl,(%edi)
	leal	1(%edi),%edi
	incl	%eax
	shrl	$8,%edx
	decl	%ebx
	jnz	.L038tail
.L035done:
	popl	%ebx
	popl	%edi
	ret
.comm	_OPENSSL_ia32cap_P,16
.section	.ctors
.long	_OPENSSL_cpuid_setup
