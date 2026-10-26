#!/usr/bin/env python3
"""Convert an ARM CMSIS-SVD chip description into a classify_mmio.py profile.

One command, SVD in, profile JSON out — the classifier itself is untouched:

    python3 svd_import.py <device.svd> <profile.json>

Output schema is exactly what classify_mmio.py consumes:
    {"chip": ..., "blocks": [{"name", "start", "end"}], "note": ...}
with start/end as "0x%08X" strings, start inclusive, end exclusive.

Block rule (one block per peripheral addressBlock, sorted by start address):
  * a peripheral's own <addressBlock> elements define its blocks:
    [baseAddress + offset, baseAddress + offset + size)
  * a <derivedFrom> peripheral inherits the source's addressBlocks (its own
    baseAddress still applies) — resolved recursively, cycles reported
  * a peripheral with no addressBlock anywhere in its chain falls back to
    its register extent (max register/cluster addressOffset + size)
  * a peripheral-level <dim> expands to one block per instance
    (name "%s" substitution, else the index appended; dimIndex ranges
    like "0-3" and lists like "A,B" both understood)

Nothing is dropped silently: every peripheral that cannot be turned into
a block is reported on stderr, and if any peripheral is skipped the tool
exits non-zero WITHOUT writing output. Register extents are also checked
against the chosen block end and any overflow is warned about (warning
only — the SVD addressBlock stays authoritative).

SVD files: community CMSIS-SVD data (github.com/cmsis-svd/cmsis-svd-data),
e.g. data/STMicro/STM32F103xx.svd, or any vendor pack's .svd.
"""
import sys
import xml.etree.ElementTree as ET


def parse_int(s):
    """SVD numbers: usually 0x-prefixed hex, sometimes plain decimal."""
    return int(s.strip(), 0)


def parse_dim_index(spec, count):
    """dimIndex: '0-3' range, '0,1,2' list, 'A,B' list, or None (0..count-1)."""
    if spec is None:
        return list(range(count))
    spec = spec.strip()
    if '-' in spec and ',' not in spec:
        lo, hi = spec.split('-', 1)
        try:
            return list(range(int(lo), int(hi) + 1))
        except ValueError:
            pass  # fall through to list parsing
    return [t.strip() for t in spec.split(',') if t.strip()]


def strip_namespaces(root):
    for el in root.iter():
        if '}' in el.tag:
            el.tag = el.tag.rsplit('}', 1)[1]
    return root


def child_text(el, tag):
    c = el.find(tag)
    return c.text.strip() if c is not None and c.text else None


class Skip(Exception):
    """A peripheral that cannot be turned into a block (reported, fatal)."""


def reg_extent(regs_el, default_size_bits):
    """Max (offset + size) over registers/clusters, honouring dim. Bits->bytes."""
    best = 0
    for reg in regs_el.findall('register'):
        off = child_text(reg, 'addressOffset')
        if off is None:
            raise Skip('register %r has no addressOffset'
                       % child_text(reg, 'name'))
        off = parse_int(off)
        size = child_text(reg, 'size')
        size = parse_int(size) if size else default_size_bits
        nbytes = (size + 7) // 8
        dim = reg.find('dim')
        if dim is not None:
            count = parse_int(dim.text)
            incr = child_text(reg, 'dimIncrement')
            if incr is None:
                raise Skip('dim register %r has no dimIncrement'
                           % child_text(reg, 'name'))
            off = off + (count - 1) * parse_int(incr)
        best = max(best, off + nbytes)
    for cl in regs_el.findall('cluster'):
        off = child_text(cl, 'addressOffset')
        if off is None:
            raise Skip('cluster %r has no addressOffset'
                       % child_text(cl, 'name'))
        off = parse_int(off)
        dim = cl.find('dim')
        if dim is not None:
            count = parse_int(dim.text)
            incr = child_text(cl, 'dimIncrement')
            if incr is None:
                raise Skip('dim cluster %r has no dimIncrement'
                           % child_text(cl, 'name'))
            # extent of one instance, then shift by the last instance
            inner = reg_extent(cl, default_size_bits)
            best = max(best, off + (count - 1) * parse_int(incr) + inner)
        else:
            best = max(best, off + reg_extent(cl, default_size_bits))
    return best


def resolve_chain(name, by_name, seen):
    """Follow derivedFrom links; return the source peripheral element."""
    if name in seen:
        raise Skip('derivedFrom cycle involving %r' % name)
    seen.add(name)
    src = by_name.get(name)
    if src is None:
        raise Skip('derivedFrom target %r not found in this SVD' % name)
    nxt = src.get('derivedFrom')
    if nxt:
        if '.' in nxt or '/' in nxt:
            raise Skip('derivedFrom %r is a path, not a plain name' % nxt)
        return resolve_chain(nxt, by_name, seen)
    return src


def main():
    if len(sys.argv) != 3:
        print('Usage: python3 svd_import.py <device.svd> <profile.json>')
        return 2
    svd_path, out_path = sys.argv[1], sys.argv[2]
    root = strip_namespaces(ET.parse(svd_path).getroot())
    device = child_text(root, 'name') or 'unknown'
    version = child_text(root, 'version') or '?'
    width = child_text(root, 'width')
    default_size = parse_int(width) if width else 32
    periph_els = root.find('peripherals')
    if periph_els is None:
        print('error: no <peripherals> in %s' % svd_path, file=sys.stderr)
        return 2
    periphs = periph_els.findall('peripheral')
    by_name = {}
    for p in periphs:
        n = child_text(p, 'name')
        if n and n not in by_name:
            by_name[n] = p

    blocks = []
    skipped = []
    stats = {'derived': 0, 'dim_expanded': 0, 'addrblock_fallback': 0,
             'extent_warnings': 0}
    for p in periphs:
        name = child_text(p, 'name')
        if not name:
            skipped.append('(unnamed peripheral element)')
            continue
        try:
            base_s = child_text(p, 'baseAddress')
            if base_s is None:
                raise Skip('no baseAddress')
            base = parse_int(base_s)
            # Resolve addressBlocks: own, else inherited via derivedFrom.
            src = p
            df = p.get('derivedFrom')
            if df:
                stats['derived'] += 1
                if '.' in df or '/' in df:
                    raise Skip('derivedFrom %r is a path' % df)
                src = resolve_chain(df, by_name, {name})
            ablocks = src.findall('addressBlock')
            if not ablocks:
                regs = src.find('registers')
                if regs is None:
                    raise Skip('no addressBlock and no registers to '
                               'fall back on')
                stats['addrblock_fallback'] += 1
                size = child_text(src, 'size')
                dsize = parse_int(size) if size else default_size
                extent = reg_extent(regs, dsize)
                ablocks = [(0, extent)]
            else:
                parsed = []
                for a in ablocks:
                    off = child_text(a, 'offset')
                    size = child_text(a, 'size')
                    if size is None:
                        raise Skip('addressBlock without <size>')
                    parsed.append((parse_int(off) if off else 0,
                                   parse_int(size)))
                ablocks = parsed
            # Register-extent sanity check (warning only).
            regs = src.find('registers')
            if regs is not None:
                try:
                    size = child_text(src, 'size')
                    dsize = parse_int(size) if size else default_size
                    ext = reg_extent(regs, dsize)
                    block_end = max(o + s for o, s in ablocks)
                    if ext > block_end:
                        print('warning: %s registers extend to %#x but '
                              'addressBlock ends at %#x (block kept)'
                              % (name, base + ext, base + block_end),
                              file=sys.stderr)
                        stats['extent_warnings'] += 1
                except Skip as e:
                    print('warning: %s: extent check skipped (%s)'
                          % (name, e), file=sys.stderr)
            # Peripheral-level dim expansion.
            dim = p.find('dim')
            if dim is not None:
                count = parse_int(dim.text)
                incr = child_text(p, 'dimIncrement')
                if incr is None:
                    raise Skip('dim peripheral without dimIncrement')
                incr = parse_int(incr)
                idxs = parse_dim_index(child_text(p, 'dimIndex'), count)
                stats['dim_expanded'] += 1
                instances = []
                for i, tok in enumerate(idxs):
                    iname = name.replace('%s', str(tok)) \
                        if '%s' in name else '%s%s' % (name, tok)
                    instances.append((iname, base + i * incr))
            else:
                instances = [(name, base)]
            for iname, ibase in instances:
                for off, size in ablocks:
                    blocks.append({'name': iname,
                                   'start': '0x%08X' % (ibase + off),
                                   'end': '0x%08X' % (ibase + off + size)})
        except Skip as e:
            skipped.append('%s: %s' % (name, e))

    if skipped:
        print('error: %d peripheral(s) could not be converted — '
              'refusing to write a partial profile:' % len(skipped),
              file=sys.stderr)
        for s in skipped:
            print('  skipped: %s' % s, file=sys.stderr)
        return 1

    blocks.sort(key=lambda b: (int(b['start'], 16), b['name']))
    profile = {
        'chip': '%s (SVD v%s)' % (device, version),
        'blocks': blocks,
        'note': ('Blocks derived from %s (device %s, SVD v%s): one block '
                 'per peripheral addressBlock, [base+offset, '
                 'base+offset+size); derivedFrom peripherals inherit the '
                 'source addressBlock; peripheral dim expanded per '
                 'instance. An address outside every block is NOT a '
                 'known local peripheral.'
                 % (svd_path.split('/')[-1], device, version)),
    }
    with open(out_path, 'w') as f:
        import json
        json.dump(profile, f, indent=1)
        f.write('\n')
    print('device: %s (SVD v%s)' % (device, version))
    print('peripherals: %d (%d derivedFrom, %d dim-expanded, '
          '%d addressBlock fallbacks, %d extent warnings)'
          % (len(periphs), stats['derived'], stats['dim_expanded'],
             stats['addrblock_fallback'], stats['extent_warnings']))
    print('blocks written: %d -> %s' % (len(blocks), out_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
