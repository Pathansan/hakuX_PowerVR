import struct
import shutil
import capstone

SO_PATH = "android/app/src/main/jniLibs/arm64-v8a/libhakuxcore.so"
shutil.copyfile(SO_PATH, SO_PATH + ".bak_v130_clean")

with open(SO_PATH + ".bak_v130_clean", "rb") as f:
    elf = bytearray(f.read())

assert len(elf) == 6852304, f"Unexpected so size: {len(elf)}"

def encode_b(from_addr, to_addr):
    offset = (to_addr - from_addr) // 4
    imm26 = offset & 0x03ffffff
    return 0x14000000 | imm26

def encode_bl(from_addr, to_addr):
    offset = (to_addr - from_addr) // 4
    imm26 = offset & 0x03ffffff
    return 0x94000000 | imm26

def encode_b_cond(from_addr, to_addr, cond):
    offset = (to_addr - from_addr) // 4
    imm19 = offset & 0x0007ffff
    return 0x54000000 | (imm19 << 5) | cond

def encode_cbz(reg, from_addr, to_addr, is_64=True):
    offset = (to_addr - from_addr) // 4
    imm19 = offset & 0x0007ffff
    op = 0xb4000000 if is_64 else 0x34000000
    return op | (imm19 << 5) | (reg & 0x1f)

def encode_adrp(reg, from_addr, to_addr):
    from_page = from_addr >> 12
    to_page = to_addr >> 12
    offset = to_page - from_page
    imm = offset & 0x1fffff
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7ffff
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (reg & 0x1f)

# Needles table (7 entries * 16 bytes = 112 bytes)
entries = [
    # 0: PB wait edx (Halo, Ninja Gaiden, NFS MW)
    (bytes([0xf7, 0xc2, 0xff, 0xff, 0xff, 0x0f]), 6, 0, 6),
    # 1: PB wait ecx (Halo)
    (bytes([0xf7, 0xc1, 0xff, 0xff, 0xff, 0x0f]), 6, 0, 6),
    # 2: BOT wait jae (NFSMW)
    (bytes([0x3d, 0x00, 0x20, 0x00, 0x00, 0x73]), 6, 1, 5),
    # 3: Present wait jb (Halo)
    (bytes([0x2b, 0xc8, 0x83, 0xf9, 0x02, 0x72]), 6, 0, 5),
    # 4: Flip spin wait jne (Halo CDevice::Destroy, CDevice::Reset, Bink)
    (bytes([0x85, 0xc0, 0x75, 0xf5]), 4, 1, 2),
    # 5: Halo main loop abort check je (0x5696f)
    (bytes([0x84, 0xc0, 0x74, 0x0a, 0xe8, 0xa8, 0x6a, 0x06]), 8, 1, 2),
    # 6: Halo subsystem abort check je (0x56a60)
    (bytes([0x84, 0xc0, 0x74, 0x0e, 0xe8, 0x77, 0xd1, 0x08]), 8, 1, 2),
]

table = bytearray(len(entries) * 16)
for i, (pat, plen, ptype, poff) in enumerate(entries):
    base_idx = i * 16
    table[base_idx : base_idx + len(pat)] = pat
    table[base_idx + 12] = plen
    table[base_idx + 13] = ptype
    table[base_idx + 14] = poff
    table[base_idx + 15] = 0

TABLE_ADDR = 0x89300
ROUTINE_ADDR = 0x89380
MEMMEM_ADDR = 0x50bc10
HOOK_ADDR = 0x2a5320
RESUME_ADDR = 0x2a5330

labels = {}
instructions = []

def emit(ins_bytes_or_fn, label=None):
    addr = ROUTINE_ADDR + len(instructions) * 4
    if label:
        labels[label] = addr
    instructions.append((addr, ins_bytes_or_fn))

for pass_num in (1, 2):
    instructions = []
    # Save callee-saved registers and lr
    emit(0xa9bd63f7, 'entry')       # stp x23, x24, [sp, #-48]!
    emit(0xa90173fb)                # stp x27, x28, [sp, #16]
    emit(0xf90013fe)                # str x30, [sp, #32]

    # x23 = &table[0] (0x89300), w24 = num_entries
    emit(encode_adrp(23, ROUTINE_ADDR + 12, TABLE_ADDR))
    emit(0x910c02f7)                # add x23, x23, #0x300
    emit(0x52800000 | (len(entries) << 5) | 24) # mov w24, #num_entries

    emit(0x394032fb, 'needle_loop') # ldrb w27, [x23, #12] (plen)
    target = labels.get('needle_next', ROUTINE_ADDR)
    emit(encode_cbz(27, ROUTINE_ADDR + len(instructions)*4, target, is_64=False))

    emit(0xaa1903fc)                # mov x28, x25 (cur_p = section_start)

    # search_loop:
    emit(0x8b1a0328, 'search_loop') # add x8, x25, x26 (end = start + len)
    emit(0xcb1c0101)                # sub x1, x8, x28 (rem = end - cur_p)
    emit(0x6b1b003f)                # cmp x1, w27, uxtw
    target = labels.get('needle_next', ROUTINE_ADDR)
    emit(encode_b_cond(ROUTINE_ADDR + len(instructions)*4, target, 3)) # b.lo needle_next

    emit(0xaa1c03e0)                # mov x0, x28 (arg0 = cur_p)
    emit(0xaa1703e2)                # mov x2, x23 (arg2 = needle pattern)
    emit(0x2a1b03e3)                # mov w3, w27 (arg3 = needle length)
    emit(encode_bl(ROUTINE_ADDR + len(instructions)*4, MEMMEM_ADDR)) # bl memmem
    target = labels.get('needle_next', ROUTINE_ADDR)
    emit(encode_cbz(0, ROUTINE_ADDR + len(instructions)*4, target, is_64=True)) # cbz x0, needle_next

    # Found match at x0! Advance search pointer:
    emit(0x8b1b001c)                # add x28, x0, w27, uxtw (cur_p = match + plen)

    # Apply patch:
    emit(0x394036e8)                # ldrb w8, [x23, #13] (ptype)
    emit(0x39403ae9)                # ldrb w9, [x23, #14] (poff)
    target = labels.get('patch_smart', ROUTINE_ADDR)
    emit(encode_cbz(8, ROUTINE_ADDR + len(instructions)*4, target, is_64=False)) # cbz w8, patch_smart

    # type 1: Explicit NOP NOP (0x9090)
    emit(0x5292120a)                # mov w10, #0x9090
    emit(0x7829480a)                # strh w10, [x0, w9, uxtw]
    target_loop = labels.get('search_loop', ROUTINE_ADDR)
    emit(encode_b(ROUTINE_ADDR + len(instructions)*4, target_loop)) # b search_loop

    # patch_smart (type 0): check pop reg (0x58..0x5F), then check 0x75 (jne) / 0x73 (jae) vs 0x74 (je) / 0x72 (jb)
    emit(0x3869480a, 'patch_smart') # ldrb w10, [x0, w9, uxtw]
    emit(0x5101614b)                # sub w11, w10, #0x58
    emit(0x7100217f)                # cmp w11, #8
    emit(0x1a892529)                # cinc w9, w9, lo (if pop reg, poff++)
    emit(0x3869480a)                # ldrb w10, [x0, w9, uxtw] (read target opcode)
    emit(0x7101d55f)                # cmp w10, #0x75 (jne)
    target_nop = labels.get('write_nop', ROUTINE_ADDR)
    emit(encode_b_cond(ROUTINE_ADDR + len(instructions)*4, target_nop, 0)) # b.eq write_nop
    emit(0x7101cd5f)                # cmp w10, #0x73 (jae)
    emit(encode_b_cond(ROUTINE_ADDR + len(instructions)*4, target_nop, 0)) # b.eq write_nop

    # Opcode is 0x74 (je) or 0x72 (jb) -> write 0xEB (jmp):
    emit(0x52801d6a)                # mov w10, #0xEB
    emit(0x3829480a)                # strb w10, [x0, w9, uxtw]
    target_loop = labels.get('search_loop', ROUTINE_ADDR)
    emit(encode_b(ROUTINE_ADDR + len(instructions)*4, target_loop)) # b search_loop

    # write_nop: write 0x9090 (NOP NOP):
    emit(0x5292120a, 'write_nop')   # mov w10, #0x9090
    emit(0x7829480a)                # strh w10, [x0, w9, uxtw]
    emit(encode_b(ROUTINE_ADDR + len(instructions)*4, target_loop)) # b search_loop

    # needle_next:
    emit(0x910042f7, 'needle_next') # add x23, x23, #16
    emit(0x71000718)                # subs w24, w24, #1
    target = labels.get('needle_loop', ROUTINE_ADDR)
    emit(encode_b_cond(ROUTINE_ADDR + len(instructions)*4, target, 1)) # b.ne needle_loop

    # Epilogue: restore callee-saved regs and lr
    emit(0xf94013fe, 'epilogue')    # ldr x30, [sp, #32]
    emit(0xa94173fb)                # ldp x27, x28, [sp, #16]
    emit(0xa8c363f7)                # ldp x23, x24, [sp], #48

    # Original displaced setup from 0x2a5320:
    emit(0xaa1903e0)                # mov x0, x25
    emit(0xaa1a03e1)                # mov x1, x26
    emit(0xaa1503e2)                # mov x2, x21
    emit(0x52800163)                # mov w3, #0xb
    emit(encode_b(ROUTINE_ADDR + len(instructions)*4, RESUME_ADDR)) # b 0x2a5330

routine_bytes = b''.join(struct.pack('<I', val) for _, val in instructions)

# 1. Place Needle Table at 0x89300
elf[TABLE_ADDR : TABLE_ADDR + len(table)] = table

# 2. Place Routine at 0x89380
elf[ROUTINE_ADDR : ROUTINE_ADDR + len(routine_bytes)] = routine_bytes

# 3. Hook at 0x2a5320: b 0x89380
hook_ins = encode_b(HOOK_ADDR, ROUTINE_ADDR)
elf[HOOK_ADDR : HOOK_ADDR + 4] = struct.pack('<I', hook_ins)

with open(SO_PATH, "wb") as f:
    f.write(elf)

print(f"Successfully patched {SO_PATH} for v1.3.0!")
print(f"Table at 0x{TABLE_ADDR:x} ({len(table)} bytes)")
print(f"Routine at 0x{ROUTINE_ADDR:x} ({len(routine_bytes)} bytes)")
print(f"Hook at 0x{HOOK_ADDR:x}: b 0x{ROUTINE_ADDR:x} (0x{hook_ins:08x})")

cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
print("\n--- Verification of Hook at 0x2a5320 ---")
for ins in cs.disasm(elf[0x2a5318 : 0x2a5338], 0x2a5318):
    h = " ".join(f"{b:02x}" for b in ins.bytes)
    print(f"0x{ins.address:06x}: {ins.mnemonic:8s} {ins.op_str:28s} ({h})")

print("\n--- Verification of Routine at 0x89380 ---")
for ins in cs.disasm(elf[ROUTINE_ADDR : ROUTINE_ADDR + len(routine_bytes)], ROUTINE_ADDR):
    h = " ".join(f"{b:02x}" for b in ins.bytes)
    print(f"0x{ins.address:06x}: {ins.mnemonic:8s} {ins.op_str:28s} ({h})")
