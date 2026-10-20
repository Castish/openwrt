#!/usr/bin/env python3
"""Actual OEM MT7626 download-mode callback and outer download dispatchers.
MMIO, allocator/OS and MCU send/response are synthetic; no physical DMA or MCU.
No source instructions are rewritten. Own analysis: SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json, struct
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R5

ROOT = Path(__file__).resolve().parent
BASE = ROOT / 'trace-stock-main.py'
ns = {'__file__': str(BASE)}
exec(compile(BASE.read_text().split('\ncases=[]')[0], str(BASE), 'exec'), ns)
MainModel = ns['MainModel']
A, H, HIF, CAP = (ns[x] for x in ('A', 'H', 'HIF', 'CAP'))
OPS = H + 0x9c4
PATCH = ns['ns']['PATCH']
FW = ns['FW']


class ModeModel(MainModel):
    def __init__(self, cfg=0x10001c75, **kw):
        super().__init__(**kw)
        self.glo = cfg
        self.accesses = []
        self.sends_with_mode = []
        self.put(OPS + 0xac, 0x40308dd0)
        self.put(OPS + 0xbc, 0x402620b0)
        self.put(A + 0x33c180, 0x402ef0e4)

        def read(uc, off, size, unused):
            assert off == 0x208 and size == 4
            self.accesses.append({'op': 'read', 'address': '0x18004208', 'value': hex(self.glo)})
            return self.glo

        def write(uc, off, size, value, unused):
            assert off == 0x208 and size == 4
            self.accesses.append({'op': 'write', 'address': '0x18004208', 'value': hex(value)})
            self.glo = value

        self.cpu.mmio_map(0x18004000, 0x1000, read, None, write, None)

    def code(self, uc, pc, size, opaque):
        if pc == 0x4033bee8 and uc.reg_read(UC_ARM_REG_R2) == 16:
            return ns['ns']['Model'].code(self, uc, pc, size, opaque)
        if pc == 0x402aaf44:
            self.sends_with_mode.append({'glo': hex(self.glo), 'send_callback': hex(self.get(OPS + 0xbc))})
        return super().code(uc, pc, size, opaque)


cases = []
# Execute the real assignment from mt7626_init, with only the enclosing context
# pointer supplied. The PC-relative constant is fetched from the unchanged image.
m = ModeModel()
m.cpu.reg_write(UC_ARM_REG_R5, OPS)
m.put(OPS + 0xac, 0)
m.cpu.emu_start(0x40309d40, 0x40309d48, count=2)
assert m.get(OPS + 0xac) == 0x40308dd0
cases.append({'case': 'actual-mt7626-init-callback-assignment', 'callback': '0x40308dd0', 'ops_offset': '0xac'})

for cfg in (0, 0x10001870, 0x10001c75, 0xa55a55aa, 0xffffffff):
    for enable in (0, 1):
        m = ModeModel(cfg)
        m.invoke(0x40308dd0, A, enable)
        expected = cfg | 0x200 if enable else cfg & ~0x200
        assert m.glo == expected
        assert m.get(OPS + 0xbc) == (0x402622ac if enable else 0x402620b0)
        assert [x['op'] for x in m.accesses] == ['read', 'write']
        cases.append({'case': f'actual-mode-{enable}-from-{cfg:08x}', 'before': hex(cfg),
                      'after': hex(m.glo), 'send_callback': hex(m.get(OPS + 0xbc)),
                      'MMIO': m.accesses})

for kind, entry in (('patch', 0x402f06c0), ('main', 0x402f0888)):
    for fail_cid in (None, 0xee):
        m = ModeModel(sync=(2, 6), fail_cid=fail_cid)
        if kind == 'patch':
            m.cpu.mem_write(FW, PATCH)
            m.put(CAP + 0x104, 1)
            m.put(A + 0x33c174, 0x402ef378)
            m.put(A + 0x33c17c, 0x402ef53c)
        else:
            # Actual selector, parser, loader and pre/post sync wrappers execute.
            m.invoke(0x402f05bc, A)
        before = m.glo
        rc = m.invoke(entry, A)
        assert rc == (5 if fail_cid else 0)
        assert m.glo == before and m.get(OPS + 0xbc) == 0x402620b0
        assert m.sends_with_mode and all(int(x['glo'], 16) & 0x200 for x in m.sends_with_mode)
        assert all(x['send_callback'] == '0x402622ac' for x in m.sends_with_mode)
        assert [x['op'] for x in m.accesses] == ['read', 'write', 'read', 'write']
        cases.append({'case': f'outer-{kind}-'+('send-failure' if fail_cid else 'success'),
                      'result': rc, 'packets': len(m.calls), 'MMIO': m.accesses,
                      'all_sends_download_mode': True, 'all_sends_FWDL3_callback': True,
                      'mode_disabled_on_exit': True})

result = {'scope': __doc__, 'source_sha256': ns['SHA'], 'cases_passed': len(cases),
          'CPU_register': '0x18004208', 'mask': '0x200', 'cases': cases,
          'limitations': ['No physical DMA, credit accounting or MCU execution',
                          'Actual outer dispatchers also select FWDL3 for commands; Linux RAM6 retains previously hardware-proven TX15 commands and FWDL3 scatter, adding only the verified mode bit',
                          'The RAM5 timeout is consistent with the omitted mode, but hardware causality is not proven by this model']}
(ROOT / 'stock-dma-mode-traces.json').write_text(json.dumps(result, indent=2) + '\n')
print(f'OEM DMA download-mode ARM model: {len(cases)} cases passed; actual callback, assignment and outer patch/main dispatchers.')
