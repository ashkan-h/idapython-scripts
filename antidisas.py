import idaapi
import idautils
import idc

for head in idautils.Heads():
    for xr in idautils.XrefsFrom(head, 0):
        if xr.type == 19:
            next = head + idaapi.get_item_size(head)

            if idc.Byte(next) == 0xFF:
                continue

            for xr2 in idautils.XrefsFrom(next, 0):
                next_next = next + idaapi.get_item_size(next)
                if (xr2.type == 19) and (xr2.to == next_next):

                    db = head + idaapi.get_item_size(head)

                    if idc.Byte(head) == 0x0F:
                        idaapi.patch_byte(head, 0x90)
                        idaapi.patch_byte(head+1, 0xE9)
                    else:
                        idaapi.patch_byte(head, 0xEB)

                    idc.MakeUnknown(db, xr.to - db + 0x10, idaapi.DOUNK_SIMPLE)
                    idc.MakeCode(xr.to)

                    i = db
                    while i < xr.to:
                        if (i+4) < xr.to:
                            idc.MakeDword(i)
                            i += 4
                        else:
                            idc.MakeByte(i)
                            i += 1

                    idaapi.analyze_area(head-0x40, head+0x40)
                    idaapi.analyze_area(xr.to-0x40, xr.to+0x40)

for head in idautils.Heads():
    if idc.Byte(head) == 0xE8:
        for xr in idautils.XrefsFrom(head, 0):
            # Find direct call targets
            if not (xr.type == 21):
                idc.MakeFunction(xr.to)