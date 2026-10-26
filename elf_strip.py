#!/usr/bin/env python3
"""Minimal ELF symbol-stripper (fallback when no cross binutils exist).

Removes .symtab, its linked .strtab, SHT_SYMTAB_SHNDX, .debug_*,
and any .rel/.rela/.group sections linked to the dropped symtab, by
rebuilding ONLY the section-header table. Program headers and all
section data stay byte-identical in place, so loading/disassembly
(Ghidra import) is unaffected; only symbol/debug visibility is gone.

Usage: python3 elf_strip.py <input.elf> <output.elf>
Verifies with: readelf -S <output.elf>  (no .symtab line)
"""
import struct
import sys


def parse_shdrs(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_data != 1:
        raise ValueError("only little-endian ELF supported")
    if ei_class == 1:  # 32-bit: e_shoff@32, e_shentsize@46,
        # e_shnum@48, e_shstrndx@50
        e_shoff = struct.unpack_from("<I", data, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 46)
        fmt, size = "<IIIIIIIIII", 40
    elif ei_class == 2:  # 64-bit
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
        fmt, size = "<IIQQQQIIQQ", 64
    else:
        raise ValueError("unknown ELF class")
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        vals = struct.unpack_from(fmt, data, off)
        shdrs.append(list(vals))
    return ei_class, e_shoff, e_shentsize, e_shnum, e_shstrndx, fmt, size, shdrs


def shdr_name(data, shstr_off, name_off):
    end = data.index(b"\x00", shstr_off + name_off)
    return data[shstr_off + name_off:end].decode("ascii", "replace")


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = bytearray(open(src, "rb").read())
    ei_class, e_shoff, e_shentsize, e_shnum, e_shstrndx, fmt, size, shdrs = (
        parse_shdrs(data))
    # Section-name string table (index 0 in 32-bit layout is sh_name).
    shstr = shdrs[e_shstrndx]
    shstr_off = shstr[4] if ei_class == 1 else shstr[4]
    names = [shdr_name(data, shstr_off, s[0]) for s in shdrs]

    # SHT_SYMTAB = 2, SHT_STRTAB = 3, SHT_SYMTAB_SHNDX = 18,
    # SHT_REL = 9, SHT_RELA = 4, SHT_GROUP = 17.
    symtab_idx = [i for i, s in enumerate(shdrs) if s[1] == 2]
    drop = set()
    for i in symtab_idx:
        drop.add(i)
        link = shdrs[i][6]  # sh_link: associated strtab
        drop.add(link)
    for i, s in enumerate(shdrs):
        if s[1] == 18:  # SYMTAB_SHNDX
            drop.add(i)
        if names[i].startswith(".debug"):
            drop.add(i)
        if s[1] in (9, 4, 17) and s[6] in drop:
            drop.add(i)  # rel/rela/group tied to the dropped symtab
    drop.discard(e_shstrndx)  # never drop the section-name table itself
    if 0 in drop:
        drop.discard(0)  # keep the null section header

    kept = [i for i in range(e_shnum) if i not in drop]
    new_index = {old: new for new, old in enumerate(kept)}
    out = bytearray(data)
    new_shoff = len(out)
    for old in kept:
        s = list(shdrs[old])
        # Fix sh_link references that pointed at dropped sections: only
        # symtab links existed; remaining links point at kept sections.
        if s[6] in new_index:
            s[6] = new_index[s[6]]
        elif s[6] != 0 and s[6] not in new_index and s[6] < e_shnum:
            s[6] = 0
        out += struct.pack(fmt, *s)
    if ei_class == 1:
        struct.pack_into("<I", out, 32, new_shoff)
        struct.pack_into("<H", out, 48, len(kept))
        struct.pack_into("<H", out, 50, new_index[e_shstrndx])
    else:
        struct.pack_into("<Q", out, 40, new_shoff)
        struct.pack_into("<H", out, 60, len(kept))
        struct.pack_into("<H", out, 62, new_index[e_shstrndx])
    open(dst, "wb").write(out)
    dropped_names = sorted(names[i] for i in drop if i != 0)
    print(f"dropped sections: {dropped_names}")
    print(f"kept {len(kept)}/{e_shnum} section headers")


if __name__ == "__main__":
    main()
