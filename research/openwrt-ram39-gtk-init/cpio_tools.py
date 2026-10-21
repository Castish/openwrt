"""Read deterministic uncompressed newc initramfs content for release checks."""
def entries(data):
    out = {}
    offset = 0
    while offset + 110 <= len(data):
        header = data[offset:offset + 110]
        assert header[:6] == b'070701', offset
        fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        assert namesize and offset + 110 + namesize <= len(data)
        rawname = data[offset + 110:offset + 110 + namesize]
        assert rawname[-1] == 0
        name = rawname[:-1].decode().lstrip('./')
        offset = (offset + 110 + namesize + 3) & ~3
        assert offset + size <= len(data)
        if name == 'TRAILER!!!':
            assert not size
            return out
        assert name not in out, name
        out[name] = (fields[1], fields[2], fields[3], fields[9], fields[10], data[offset:offset + size])
        offset = (offset + size + 3) & ~3
    raise AssertionError('Missing newc trailer')

def compare_qemu(hardware, qemu, helper):
    a, b = entries(hardware), entries(qemu)
    name = 'usr/sbin/c80-net-selftest'
    assert name not in a and b.pop(name)[5] == helper
    assert a == b
    return len(a)
