"""Offline analysis of zprobe dumps:
   - protobuf wire-format walk (schema-less) for ServerResponseMsg
   - Shannon entropy + ECB/block-repeat detection for the Zstd input
Usage:
   python pbwalk.py walk  <file>
   python pbwalk.py ent   <file> [block]
"""
import sys, math, collections

def read_varint(b, i):
    r = 0; s = 0
    while i < len(b):
        c = b[i]; i += 1
        r |= (c & 0x7f) << s
        if not (c & 0x80):
            return r, i
        s += 7
        if s > 70:
            raise ValueError("varint too long")
    raise ValueError("eof")

def walk(b, indent=0, depth=0, maxdepth=3):
    out = []
    i = 0
    while i < len(b):
        try:
            key, i = read_varint(b, i)
        except Exception as e:
            out.append(" " * indent + f"<stop @{i}: {e}>")
            break
        f = key >> 3; wt = key & 7
        if wt == 0:
            try:
                v, i = read_varint(b, i)
            except Exception as e:
                out.append(" " * indent + f"<varint eof @{i}>"); break
            out.append(" " * indent + f"field {f} varint = {v}")
        elif wt == 1:
            v = int.from_bytes(b[i:i+8], "little"); i += 8
            out.append(" " * indent + f"field {f} fixed64 = {v}")
        elif wt == 2:
            try:
                n, i = read_varint(b, i)
            except Exception:
                out.append(" " * indent + f"<len eof @{i}>"); break
            chunk = b[i:i+n]; i += n
            pr = sum(1 for c in chunk if 32 <= c < 127)
            note = ""
            if n > 0 and pr * 100 // n >= 85:
                note = f'  ascii="{chunk[:70].decode("latin1")}"'
            out.append(" " * indent + f"field {f} bytes len={n}{note}")
            out.append(" " * indent + f"    raw={chunk[:48].hex()}")
            if depth < maxdepth and n >= 2:
                try:
                    sub = walk(chunk, indent + 6, depth + 1, maxdepth)
                    if sub and not (len(sub) == 1 and sub[0].strip().startswith("<stop @0")):
                        out.extend(sub)
                except Exception:
                    pass
        elif wt == 5:
            v = int.from_bytes(b[i:i+4], "little"); i += 4
            out.append(" " * indent + f"field {f} fixed32 = {v}")
        else:
            out.append(" " * indent + f"field {f} wiretype={wt} UNSUPPORTED (stop)")
            break
    return out

def entropy(data):
    if not data:
        return 0.0
    c = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def analyze_ent(path, block=16):
    b = open(path, "rb").read()
    print(f"file={path} size={len(b)}")
    print(f"shannon entropy = {entropy(b):.4f} bits/byte (max 8.0)")
    print(f"head32 = {b[:32].hex()}")
    print(f"tail32 = {b[-32:].hex()}")
    if len(b) >= 4:
        print(f"first4 = {b[:4].hex()}  zstd_magic={'YES' if b[:4] == bytes([0x28,0xB5,0x2F,0xFD]) else 'no'}")
    blocks = [b[i:i+block] for i in range(0, len(b) - block + 1, block)]
    dup = [k for k, v in collections.Counter(blocks).items() if v > 1]
    print(f"distinct {block}B blocks = {len(set(blocks))}/{len(blocks)}   repeated={len(dup)}")
    if dup:
        print("  ** repeated blocks => ECB/fixed keystream fingerprint **")
        for d in dup[:4]:
            print("   ", d.hex())
    zero = sum(1 for c in b if c == 0)
    print(f"zero bytes = {zero} ({zero*100.0/max(len(b),1):.2f}%)")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "walk"
    path = sys.argv[2]
    if mode == "walk":
        data = open(path, "rb").read()
        print(f"=== protobuf walk of {path} ({len(data)} bytes) ===")
        print("\n".join(walk(data)))
    else:
        analyze_ent(path, int(sys.argv[3]) if len(sys.argv) > 3 else 16)
