with open("/dev/urandom", "rb") as f:
    data = b""
    i = 0
    while True:
        data += f.read(10000000)  # 10mb
        i += 1
        print(f"{i*10}mb")
