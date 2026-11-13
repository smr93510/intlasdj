import ctypes, sys

def read(pid, addr, n):
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    PROC_VM_READ = 0x0010
    PROC_QUERY = 0x0400
    h = k.OpenProcess(PROC_VM_READ | PROC_QUERY, False, pid)
    if not h:
        return None, f"OpenProcess failed err={ctypes.get_last_error()}"
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    ok = k.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, ctypes.c_size_t(n), ctypes.byref(got))
    k.CloseHandle(h)
    if not ok:
        return None, f"RPM failed err={ctypes.get_last_error()}"
    return buf.raw[:got.value], None

def main():
    pid = int(sys.argv[1])
    for spec in sys.argv[2:]:
        try:
            off16, n = spec.split(":")
            addr = int(off16, 16)
            n = int(n)
        except ValueError:
            print("bad spec", spec); continue
        data, err = read(pid, addr, n)
        if err:
            print(f"[0x{addr:X}] {err}")
            continue
        print(f"[0x{addr:X}] read {len(data)}B")
        print(data.hex())

main()
