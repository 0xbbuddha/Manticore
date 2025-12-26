


if __name__ == "__main__":
    with open(f"ascii.go", "w") as f:
        f.write(f"package ascii\n\n")

        f.write(f"// ASCIICharset\n")
        f.write(f"var ASCIICharset = [...]uint8" + "{")
        for key in range(256):
            if key % 16 == 0 : f.write('\n\t')
            f.write(f"0x{key:02x}, " )
        f.write('\n}\n\n')
