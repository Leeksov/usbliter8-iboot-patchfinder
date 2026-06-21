#!/usr/bin/env python3
"""
iboot_patcher.py — A13 iBoot patcher for usbliter8 jailbreak chain.

Based on vphone-cli IBootPatcher pattern-matching approach.
Uses capstone for disassembly and keystone for assembly.
No hardcoded offsets — all patches found by semantic anchoring.

Usage:
    iboot_patcher.py <input.raw> <output.raw> [--base 0x870000000] [--mode ibss|ibec|llb]
"""

import argparse
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import *

cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cs.detail = True

NOP       = struct.pack('<I', 0xD503201F)
RET       = struct.pack('<I', 0xD65F03C0)
RETAB     = struct.pack('<I', 0xD65F0FFF)
MOV_X0_0  = struct.pack('<I', 0xD2800000)
MOV_X0_1  = struct.pack('<I', 0xD2800020)
MOV_W0_0  = struct.pack('<I', 0x52800000)
MOV_W0_1  = struct.pack('<I', 0x52800020)


def rd32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def wr32(data, off, val):
    struct.pack_into("<I", data, off, val)

def disasm_at(data, off, count=10):
    return list(cs.disasm(bytes(data[off:off + count * 4]), off))


class IBootPatcher:
    def __init__(self, data, base=0x870000000, mode='ibec', verbose=True):
        self.data = bytearray(data)
        self.base = base
        self.mode = mode
        self.verbose = verbose
        self.patches = []

    def log(self, msg):
        if self.verbose:
            print(msg)

    def emit(self, off, patch_bytes, desc):
        orig = bytes(self.data[off:off + len(patch_bytes)])
        self.data[off:off + len(patch_bytes)] = patch_bytes
        self.patches.append((off, orig, patch_bytes, desc))
        va = self.base + off
        self.log(f"  0x{off:06X} (VA 0x{va:X}): {desc}")

    def find_string(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        idx = self.data.find(needle)
        return idx if idx >= 0 else None

    def find_all_strings(self, needle):
        if isinstance(needle, str):
            needle = needle.encode()
        results = []
        start = 0
        while True:
            idx = self.data.find(needle, start)
            if idx < 0:
                break
            results.append(idx)
            start = idx + 1
        return results

    def find_adrp_add_refs(self, target_off):
        """Find ADRP+ADD pairs that reference target_off."""
        target_page = target_off & ~0xFFF
        target_pageoff = target_off & 0xFFF
        refs = []
        for off in range(0, min(len(self.data) - 4, 0x140000), 4):
            insn_word = rd32(self.data, off)
            if (insn_word & 0x9F000000) != 0x90000000:
                continue
            immlo = (insn_word >> 29) & 0x3
            immhi = (insn_word >> 5) & 0x7FFFF
            imm = ((immhi << 2) | immlo) << 12
            if imm & (1 << 32):
                imm |= ~0x1FFFFFFFF
            adrp_target = (off & ~0xFFF) + (imm & 0xFFFFFFFF)
            if (adrp_target & 0xFFFFFFFF) != (target_page & 0xFFFFFFFF):
                continue
            next_off = off + 4
            if next_off + 4 > len(self.data):
                continue
            next_word = rd32(self.data, next_off)
            if (next_word & 0xFFC00000) == 0x91000000:
                add_imm = (next_word >> 10) & 0xFFF
                shift = (next_word >> 22) & 0x3
                if shift == 1:
                    add_imm <<= 12
                if add_imm == target_pageoff:
                    rd = insn_word & 0x1F
                    add_rd = next_word & 0x1F
                    add_rn = (next_word >> 5) & 0x1F
                    if add_rn == rd:
                        refs.append(off)
        return refs

    # ═══════════════════════════════════════════
    # Patch 1: image4_validate_property_callback
    # ═══════════════════════════════════════════

    def patch_image4_callback(self):
        """
        Find image4 property validation callback epilogue:
          MOV W<reg>, #-1        (set error return)
          ...
          CMP <canary check>
          B.NE <stack_chk_fail>  ← NOP this
          MOV X0, X<reg>         ← MOV X0, #0
          ...
          RETAB
        """
        self.log("\n[*] Patching image4_validate_property_callback...")

        CHUNK = 0x2000
        OVERLAP = 0x100
        found = False

        for start in range(0, min(len(self.data), 0x140000), CHUNK - OVERLAP):
            end = min(start + CHUNK, len(self.data))
            insns = list(cs.disasm(bytes(self.data[start:end]), start))

            for i, insn in enumerate(insns):
                if insn.mnemonic != 'b.ne' or i + 1 >= len(insns):
                    continue
                next_insn = insns[i + 1]
                if next_insn.mnemonic != 'mov':
                    continue
                if 'x0' not in next_insn.op_str or 'x' not in next_insn.op_str.split(',')[-1].strip():
                    continue

                src_reg = next_insn.op_str.split(',')[-1].strip()
                if not src_reg.startswith('x'):
                    continue

                has_cmp = False
                for j in range(max(0, i - 8), i):
                    if insns[j].mnemonic == 'cmp':
                        has_cmp = True
                        break

                if not has_cmp:
                    continue

                has_movn = False
                for j in range(max(0, i - 64), i):
                    mn = insns[j].mnemonic
                    ops = insns[j].op_str
                    w_reg = src_reg.replace('x', 'w')
                    if (mn == 'movn' and w_reg in ops) or (mn == 'mov' and w_reg in ops and '#-1' in ops) or (mn == 'mov' and w_reg in ops and '#0xffffffff' in ops.lower()):
                        has_movn = True
                        break

                if not has_movn:
                    continue

                self.emit(insn.address, NOP, f"NOP b.ne (image4 canary → stack_chk_fail)")
                self.emit(next_insn.address, MOV_X0_0, f"MOV X0, #0 (force image4 callback success)")
                found = True
                break

            if found:
                break

        if not found:
            self.log("  [!] image4 callback patch NOT FOUND")
        return found

    # ═══════════════════════════════════════════
    # Patch 2: boot-args override
    # ═══════════════════════════════════════════

    def patch_boot_args(self):
        """
        Find "%s" near "rd=md0", redirect ADRP+ADD to custom boot-args string.
        """
        if self.mode == 'ibss':
            return False

        self.log("\n[*] Patching boot-args...")

        rd_md0 = self.find_string("rd=md0")
        if rd_md0 is None:
            self.log("  [!] 'rd=md0' not found")
            return False

        fmt_s = None
        for off in range(max(0, rd_md0 - 0x100), rd_md0 + 0x100):
            if self.data[off:off+3] == b'%s\x00':
                fmt_s = off
                break

        if fmt_s is None:
            self.log("  [!] '%s' format string not found near rd=md0")
            return False

        new_args = b"serial=3 -v debug=0x2014e %s\x00"
        slot = None
        for off in range(0x14000, len(self.data) - 64):
            if self.data[off:off + 64] == b'\x00' * 64:
                if off % 16 == 0:
                    slot = off
                    break

        if slot is None:
            self.log("  [!] No NUL slot found for boot-args string")
            return False

        self.emit(slot, new_args, f"Write boot-args string at 0x{slot:X}")

        refs = self.find_adrp_add_refs(fmt_s)
        if not refs:
            self.log("  [!] No ADRP+ADD refs to '%s' found")
            return False

        for ref_off in refs:
            target_page = slot & ~0xFFF
            target_pageoff = slot & 0xFFF
            pc_page = ref_off & ~0xFFF
            page_delta = (target_page - pc_page) >> 12

            orig_adrp = rd32(self.data, ref_off)
            rd = orig_adrp & 0x1F
            immlo = page_delta & 0x3
            immhi = (page_delta >> 2) & 0x7FFFF
            new_adrp = 0x90000000 | (immlo << 29) | (immhi << 5) | rd
            self.emit(ref_off, struct.pack("<I", new_adrp), f"ADRP redirect to boot-args")

            orig_add = rd32(self.data, ref_off + 4)
            add_rd = orig_add & 0x1F
            add_rn = (orig_add >> 5) & 0x1F
            new_add = 0x91000000 | (target_pageoff << 10) | (add_rn << 5) | add_rd
            self.emit(ref_off + 4, struct.pack("<I", new_add), f"ADD redirect to boot-args offset")

        return True

    # ═══════════════════════════════════════════
    # Patch 3: CTRR lockdown skip
    # ═══════════════════════════════════════════

    def patch_ctrr_lockdown(self):
        """
        Find MSR to CTRR_LOCK register and NOP it.
        CTRR_LOCK_EL2 = s3_4_c15_c2_2 (encoding varies).
        Also NOP the CTRR_CTL enable writes.
        """
        self.log("\n[*] Patching CTRR lockdown...")

        patched = 0
        for off in range(0, min(len(self.data), 0x140000) - 4, 4):
            word = rd32(self.data, off)
            if (word & 0xFFF00000) != 0xD5100000:
                continue

            op0 = 2 + ((word >> 19) & 1)
            op1 = (word >> 16) & 0x7
            crn = (word >> 12) & 0xF
            crm = (word >> 8) & 0xF
            op2 = (word >> 5) & 0x7

            is_ctrr = False
            desc = ""

            if op0 == 3 and op1 == 4 and crn == 15 and crm == 2:
                if op2 == 2:
                    is_ctrr = True
                    desc = "CTRR_LOCK_EL2"
                elif op2 == 5:
                    is_ctrr = True
                    desc = "CTRR_CTL_EL2"
                elif op2 == 3:
                    desc = "CTRR_A_LWR_EL2"
                elif op2 == 4:
                    desc = "CTRR_A_UPR_EL2"

            if op0 == 3 and op1 == 4 and crn == 15 and crm == 1:
                if op2 == 7:
                    desc = "CTRR_B_LWR_EL2"
                elif op2 == 6:
                    desc = "CTRR_B_UPR_EL2"

            if is_ctrr:
                self.emit(off, NOP, f"NOP MSR {desc}")
                patched += 1

        if patched == 0:
            self.log("  [!] No CTRR lock/ctl MSR instructions found")
        else:
            self.log(f"  [{patched} CTRR MSR instructions NOP'd]")
        return patched > 0

    # ═══════════════════════════════════════════
    # Patch 4: Signature check bypass (generic)
    # ═══════════════════════════════════════════

    def patch_signature_check(self):
        """
        Find 'ticket' or 'img4' related signature verification
        and patch conditional branches to unconditional.
        """
        self.log("\n[*] Looking for signature verification anchors...")

        for needle in ["ticket.der", "image4_callbacks"]:
            off = self.find_string(needle)
            if off:
                self.log(f"  Found '{needle}' @ 0x{off:X}")

        return False

    # ═══════════════════════════════════════════
    # Run all patches
    # ═══════════════════════════════════════════

    def patch_all(self):
        self.log(f"=== iBoot Patcher (mode={self.mode}, base=0x{self.base:X}) ===")
        self.log(f"Input size: {len(self.data)} bytes")

        version = self.find_string(b"iBoot for")
        if version:
            end = self.data.find(b'\x00', version)
            self.log(f"Version: {self.data[version:end].decode('ascii', errors='replace')}")

        self.patch_image4_callback()

        if self.mode in ('ibec', 'llb'):
            self.patch_boot_args()

        self.patch_ctrr_lockdown()
        self.patch_signature_check()

        self.log(f"\n=== {len(self.patches)} patches applied ===")
        return self.data


def main():
    parser = argparse.ArgumentParser(description="A13 iBoot patcher for usbliter8")
    parser.add_argument("input", type=Path, help="decrypted iBoot raw binary")
    parser.add_argument("output", type=Path, help="patched output file")
    parser.add_argument("--base", default="0x870000000", help="iBoot base address (default: 0x870000000)")
    parser.add_argument("--mode", choices=["ibss", "ibec", "llb"], default="ibec", help="iBoot component mode")
    parser.add_argument("-q", "--quiet", action="store_true")

    args = parser.parse_args()
    base = int(args.base, 0)
    data = args.input.read_bytes()

    patcher = IBootPatcher(data, base=base, mode=args.mode, verbose=not args.quiet)
    patched = patcher.patch_all()

    args.output.write_bytes(bytes(patched))
    print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
