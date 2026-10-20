"""Read-only check of the small CRC-checked TFTP script that will be issued."""
import hashlib,zlib

def validate_script(root, records):
    rows=(root/'c80-start.txt').read_text().splitlines()
    assert rows[:2]==['C80SCRIPT1','# All numeric fields are hexadecimal.']
    assert len(rows)==7 and rows[-2:]==['go 40e00000','end']
    intervals=[]
    for line,record in zip(rows[2:5],records,strict=True):
        verb,address,name,length,crc=line.split()
        assert verb=='load' and address==record['address'] and name==record['file']
        data=(root/name).read_bytes();start=int(address,16);stop=start+len(data)
        assert len(data)==int(length,16)==record['bytes'] and zlib.crc32(data)==int(crc,16)
        assert hashlib.sha256(data).hexdigest()==record['sha256']
        assert start>=0x40200000 and stop<=0x41c00000 and start%4==0
        for a,b in [(0x40280000,0x40290000),(0x40a00000,0x40a10000),*intervals]:
            assert not(start<b and a<stop)
        intervals.append((start,stop))
