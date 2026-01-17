/*
  ============================================================================
  ActiveBreach Engine Detection Pack (E-900U) — Public Ruleset
  ============================================================================

  Author
    - TITAN Softwork Solutions
*/

import "pe"

rule ActiveBreach_RS_Thread_SyscallStub_Write_4C8BD1B8
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "thread/spawn"
    technique   = "syscall-stub write"
    confidence  = "very-high"
    severity    = "high"
    description = "Rust thread spawn path writes a minimal syscall stub via byte stores (4C 8B D1 B8 .. 0F 05 C3)."

  strings:
    $stub_write = {
      C7 07 4C 8B D1 B8      /* mov dword [rdi], 0xB8D18B4C  (4C 8B D1 B8) */
      88 5F 04               /* [rdi+4] = bl                 */
      88 7F 05               /* [rdi+5] = bh                 */
      88 47 06               /* [rdi+6] = al                 */
      88 4F 07               /* [rdi+7] = cl                 */
      66 C7 47 08 0F 05      /* [rdi+8] = 0F 05              */
      C6 47 0A C3            /* [rdi+0xA] = C3               */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $stub_write
}

rule ActiveBreach_RS_Thread_SyscallStub_WipeAndFree
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "thread/spawn"
    technique   = "stub wipe + free"
    confidence  = "high"
    severity    = "medium"
    description = "Rust thread spawn path wipes the syscall stub buffer and releases it via VirtualFree(MEM_RELEASE)."

  strings:
    $wipe_free = {
      41 B8 00 80 00 00        /* mov r8d, 0x8000            */
      C5 F9 EF C0              /* vpxor xmm0, xmm0, xmm0     */
      C5 FE 7F 07              /* vmovdqu ymmword [rdi], ymm0*/
      48 89 F9                 /* mov rcx, rdi               */
      31 D2                    /* xor edx, edx               */
      C5 F8 77                 /* vzeroupper                 */
      FF 15 ?? ?? ?? ??        /* call [VirtualFree]         */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $wipe_free
}

rule ActiveBreach_RS_Thread_Spawn_Guards_Stage2_AndPtrNonNull
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "thread/spawn"
    technique   = "stage/ptr guards"
    confidence  = "medium-high"
    severity    = "low"
    description = "Rust thread spawn path uses a stage==2 gate and a required non-null pointer check prior to stub creation."

  strings:
    $guards = {
      48 8B 05 ?? ?? ?? ??      /* mov rax, [rel ...]        */
      48 83 F8 02               /* cmp rax, 2                */
      75 ??                     /* jne ...                   */
      48 83 3D ?? ?? ?? ?? 00   /* cmp qword [rel ...], 0    */
      74 ??                     /* je ...                    */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $guards
}

rule ActiveBreach_Thread_Spawn_Composite
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "thread/spawn"
    confidence  = "very-high"
    severity    = "critical"
    description = "Composite: Rust thread spawn path with syscall stub write + (guards or wipe/free)."
    guidance    = "Recommended for alerting; keep component rules enabled for enrichment."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    ActiveBreach_RS_Thread_SyscallStub_Write_4C8BD1B8 and
    (
      ActiveBreach_RS_Thread_Spawn_Guards_Stage2_AndPtrNonNull or
      ActiveBreach_RS_Thread_SyscallStub_WipeAndFree
    )
}

rule ActiveBreach_RS_Mapper_Buffer_NtQueryVirtualMemory_Prime
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "mapper/buffer"
    confidence  = "medium-high"
    severity    = "medium"
    description = "Rust mapper/buffer primes NtQueryVirtualMemory using a distinctive setup + vzeroupper call sequence."

  strings:
    $nqvm_prime = {
      FF 15 ?? ?? ?? ??          /* call [GetCurrentProcess]            */
      48 8B 15 ?? ?? ?? ??       /* mov rdx, [rel NtQueryVirtualMemory] */
      48 8D 4D 38                /* lea rcx, [rbp+0x38]                 */
      4C 8D 4D 60                /* lea r9,  [rbp+0x60]                 */
      C5 F8 57 C0                /* vxorps xmm0, xmm0, xmm0             */
      C5 FC 11 45 70             /* vmovups [rbp+0x70], ymm0            */
      C5 FC 11 45 60             /* vmovups [rbp+0x60], ymm0            */
      48 C7 45 38 00 00 00 00    /* [rbp+0x38] = 0                       */
      48 C7 44 24 20 30 00 00 00 /* [rsp+0x20] = 0x30                    */
      45 31 C0                   /* xor r8d, r8d                         */
      48 89 C1                   /* mov rcx, rax                         */
      C5 F8 77                   /* vzeroupper                           */
      FF D2                      /* call rdx                             */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $nqvm_prime
}

rule ActiveBreach_RS_Exports_ExSyscalls_Rust_PEWalk_AndStubProbe
{
  meta:
    family      = "ActiveBreach"
    variant     = "Rust"
    component   = "exports/ExSyscalls"
    confidence  = "high"
    severity    = "high"
    description = "Rust ExSyscalls: PE export walk + Nt* prefix filter + syscall-stub probe behavior."

  strings:
    $mz_pe_exp88 = {
      66 81 39 4D 5A                 /* cmp word [rcx], 'MZ'                 */
      4C 63 49 3C                    /* movsxd r9, dword [rcx+0x3c]          */
      42 81 3C 09 50 45 00 00        /* cmp dword [rcx+r9], 'PE\\0\\0'       */
      46 8B 94 09 88 00 00 00        /* mov r10d, dword [rcx+r9+0x88]        */
    }

    $nt_prefix = {
      E8 ?? ?? ?? ??                 /* call strlen                          */
      48 83 F8 03                    /* cmp rax, 3                           */
      0F 82 ?? ?? ?? ??              /* jb ...                               */
      66 41 81 3E 4E 74              /* cmp word [r14], "Nt"                 */
    }

    $stub_probe = {
      81 FA B8 00 00 00              /* cmp edx, 0xB8                        */
      74 ??                          /* je ...                               */
      83 FA 4D                       /* cmp edx, 0x4D                        */
      74 ??                          /* je ...                               */
      83 FA 4C                       /* cmp edx, 0x4C                        */
    }

    $8bd1b8 = {
      80 7C 0A 01 8B
      80 7C 0A 02 D1
      80 7C 0A 03 B8
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $mz_pe_exp88 and $nt_prefix and ( $stub_probe or $8bd1b8 )
}

rule ActiveBreach_CXX_Crypto_decstr_transform
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "crypto/decstr"
    confidence  = "high"
    severity    = "high"
    description = "C++ crypto primitive: decstr byte-transform loop (xor/ror/imul invariant)."

  strings:
    $ds_a5 = { 0F B6 79 10 48 8B D9 40 80 F7 A5 }

    $ds_round = {
      0F B6 C1          /* movzx eax, cl                 */
      6B D0 11          /* imul  edx, eax, 0x11          */
      0F B6 C1          /* movzx eax, cl                 */
      02 C0             /* add   al, al                  */
      34 5F             /* xor   al, 0x5F                */
      41 32 14 08       /* xor   dl, byte [r8+rcx]       */
      C0 CA 03          /* ror   dl, 3                   */
      2A D0             /* sub   dl, al                  */
      8D 04 0F          /* lea   eax, [rdi+rcx]          */
      32 D0             /* xor   dl, al                  */
    }

    $ds_store = { 88 14 08 48 FF C1 48 3B 4B 10 72 ?? }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $ds_round and 1 of ($ds_a5, $ds_store)
}

rule ActiveBreach_CXX_Crypto_hash_deadbeef_final
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "crypto/hash"
    confidence  = "high"
    severity    = "high"
    description = "C++ crypto primitive: hash finalization uses DEADC0DECAFEBEEF constant and SIMD path markers."

  strings:
    $hf_const = { 48 B9 EF BE FE CA DE C0 AD DE 48 33 C1 }

    $hf_avx2  = { C5 FE 6F 0D ?? ?? ?? ?? C5 FE 6F 25 ?? ?? ?? ?? C5 F5 EF C8 C4 E2 7D 00 C4 }

    $hf_sse   = { 66 0F 6F 1D ?? ?? ?? ?? 66 0F 38 00 D3 }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $hf_const and ( $hf_avx2 or $hf_sse )
}

rule ActiveBreach_CXX_Launch_service_hash_constants
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "launch/service-select"
    confidence  = "high"
    severity    = "high"
    description = "C++ launch/service-select uses distinctive imm64 constant pair + compare flow."

  strings:
    $svc_pair = {
      49 BD D3 64 FE DC 4B C2 C7 BC
      49 BC F5 64 FE E2 B2 C0 9E EE
    }

    $svc_cmp  = { 49 3B C5 75 ?? 8B 73 30 EB ?? 49 3B C4 75 ?? 44 8B 73 30 }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $svc_pair and $svc_cmp
}

rule ActiveBreach_CXX_Stubs_StubPool_initialize
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "stubs/stub_pool"
    confidence  = "high"
    severity    = "high"
    description = "C++ stub pool init allocates pool, decrypts blocks, then VirtualProtect to RX."

  strings:
    $pool_alloc = {
      33 C9
      48 8B 52 10
      41 B9 04 00 00 00
      48 C1 E2 04
      41 B8 00 30 00 00
      FF 15 ?? ?? ?? ??
      48 89 05 ?? ?? ?? ??
      4C 8B F0
      48 85 C0
    }

    $pool_xor_xmm = {
      F3 0F 6F 0D ?? ?? ?? ??
      F3 0F 6F 05 ?? ?? ?? ??
      0F 57 C8
      F3 41 0F 7F 0E
    }

    $pool_xor_loop = {
      42 0F B6 04 29
      32 04 19
      41 88 04 0E
      48 FF C1
      48 83 F9 10
      7C ??
    }

    $pool_rx = {
      4C 8D 4C 24 50
      41 B8 20 00 00 00
      C7 44 24 50 00 00 00 00
      49 8B CE
      FF 15 ?? ?? ?? ??
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $pool_alloc and $pool_rx and ( $pool_xor_xmm or $pool_xor_loop )
}

rule ActiveBreach_CXX_Stubs_CreateEphemeralStub
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "stubs/ephemeral"
    confidence  = "high"
    severity    = "high"
    description = "C++ ephemeral stub creation: VirtualAlloc(0x1000) -> VirtualProtect(RX) -> VirtualFree on failure."

  strings:
    $eph_alloc = {
      BA 00 10 00 00
      33 C9
      41 B9 04 00 00 00
      41 B8 00 30 00 00
      FF 15 ?? ?? ?? ??
      48 8B D8
      48 85 C0
    }

    $eph_protect = {
      4C 8D 4C 24 20
      BA 00 10 00 00
      41 B8 20 00 00 00
      48 8B C8
      0F 11 00
      C7 44 24 20 00 00 00 00
      FF 15 ?? ?? ?? ??
      85 C0
    }

    $eph_fail_vfree = { 33 D2 41 B8 00 80 00 00 48 8B CB FF 15 ?? ?? ?? ?? }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $eph_alloc and $eph_protect and $eph_fail_vfree
}

rule ActiveBreach_CXX_Dispatch_InitEvent_ThreadProc
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "dispatch"
    confidence  = "medium-high"
    severity    = "medium"
    description = "C++ dispatch init: CreateEventW + worker thread procedure + optional wait(INFINITE) pattern."

  strings:
    $evt_create = {
      45 33 C9
      45 33 C0
      BA 01 00 00 00
      33 C9
      FF 15 ?? ?? ?? ??
      48 89 05 ?? ?? ?? ??
      48 85 C0
    }

    $threadproc = {
      48 83 EC 28
      48 8B 0D ?? ?? ?? ??
      48 85 C9
      74 06
      FF 15 ?? ?? ?? ??
      33 C0
      48 83 C4 28
      C3
    }

    $wait_inf = { BA FF FF FF FF 48 8B 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    2 of ($evt_create, $threadproc, $wait_inf)
}

rule ActiveBreach_CXX_Engine_Composite
{
  meta:
    family      = "ActiveBreach"
    variant     = "C++"
    component   = "engine/composite"
    confidence  = "very-high"
    severity    = "critical"
    description = "Composite: C++ engine present (crypto core + at least one engine behavior)."
    guidance    = "Recommended for alerting; keep component rules enabled for enrichment."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    (
      ( ActiveBreach_CXX_Crypto_decstr_transform or ActiveBreach_CXX_Crypto_hash_deadbeef_final )
      and
      1 of (
        ActiveBreach_CXX_Launch_service_hash_constants,
        ActiveBreach_CXX_Stubs_StubPool_initialize,
        ActiveBreach_CXX_Stubs_CreateEphemeralStub,
        ActiveBreach_CXX_Dispatch_InitEvent_ThreadProc
      )
    )
}

rule ActiveBreach_C_ab_hash_core
{
  meta:
    family      = "ActiveBreach"
    variant     = "C"
    component   = "crypto/ab_hash"
    confidence  = "high"
    severity    = "high"
    description = "C variant: ab_hash core loop invariant (DEADC0DECAFEBEEF seed + ror 0x3b + add 0x1337BEEF)."

  strings:
    $ab_hash_loop = {
      48 B9 EF BE FE CA DE C0 AD DE      /* mov rcx, 0xDEADC0DECAFEBEEF */
      84 C0                              /* test al, al                 */
      74 ??                              /* je ...                      */
      66 90                              /* nop                         */
      0F B6 C0                           /* movzx eax, al               */
      4D 8D 40 01                        /* lea r8, [r8+1]              */
      48 33 C8                           /* xor rcx, rax                */
      41 0F B6 00                        /* movzx eax, byte [r8]        */
      48 C1 C9 3B                        /* ror rcx, 0x3b               */
      48 81 C1 EF BE 37 13               /* add rcx, 0x1337BEEF         */
      84 C0                              /* test al, al                 */
      75 ??                              /* jne ...                     */
      48 8B C1                           /* mov rax, rcx                */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    filesize < 5MB and
    $ab_hash_loop
}

rule ActiveBreach_C_syscall_stub_builder
{
  meta:
    family      = "ActiveBreach"
    variant     = "C"
    component   = "syscall/stub_builder"
    confidence  = "high"
    severity    = "high"
    description = "C variant: syscall stub builder emits 4C 8B D1 B8 .. 0F 05 C3 via immediate stores."

  strings:
    $stub_builder = {
      C7 07 4C 8B D1 B8
      89 47 04
      66 C7 47 08 0F 05
      C6 47 0A C3
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    filesize < 5MB and
    $stub_builder
}

rule ActiveBreach_C_dispatcher_jmp_table
{
  meta:
    family      = "ActiveBreach"
    variant     = "C"
    component   = "dispatch/jmp_table"
    confidence  = "medium"
    severity    = "medium"
    description = "C variant: dispatcher computed jump via table (mov eax,[base+idx*4+off] ; add rax,base ; jmp rax)."

  strings:
    $dispatcher_jmp = { 8B 84 86 D4 1C 00 00 48 03 C6 FF E0 }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    filesize < 5MB and
    $dispatcher_jmp
}

rule ActiveBreach_C_FINAL
{
  meta:
    family      = "ActiveBreach"
    variant     = "C"
    component   = "engine/composite"
    confidence  = "very-high"
    severity    = "critical"
    description = "Composite: C variant (ab_hash core + syscall stub builder or dispatcher jump-table)."
    guidance    = "Recommended for alerting; keep component rules enabled for enrichment."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    ActiveBreach_C_ab_hash_core and
    ( ActiveBreach_C_syscall_stub_builder or ActiveBreach_C_dispatcher_jmp_table )
}

rule ActiveBreach_UNIFIED_AnyStrongSignal
{
  meta:
    family      = "ActiveBreach"
    variant     = "Unified"
    component   = "unified/strong-signal"
    confidence  = "very-high"
    severity    = "critical"
    description = "Unified alert: strong composite match for ActiveBreach across C/C++/Rust implementations."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    (
      ActiveBreach_Thread_Spawn_Composite or
      ActiveBreach_CXX_Engine_Composite or
      ActiveBreach_C_FINAL
    )
}