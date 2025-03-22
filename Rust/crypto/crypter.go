package main

import (
	"bufio"
	"fmt"
	"os"
)

func rol16(x uint16, r uint) uint16 {
	return ((x << r) | (x >> (16 - r))) & 0xFFFF
}

func encodeByte(b byte, i int) uint16 {

	x := uint16(b)
	x ^= uint16(i*13) ^ 0xAA
	x = rol16(x, uint(i%7+1))
	x = ^x + 0x1337
	x = x*7 + (0x1234 ^ uint16(i*73))

	return x
}

func encodeString(s string) []uint16 {
	out := make([]uint16, len(s))

	for i := len(s) - 1; i >= 0; i-- {
		out[len(s)-1-i] = encodeByte(s[i], i)
	}

	return out
}

func main() {
	f, err := os.Open("input.dat")

	if err != nil {
		fmt.Println("failed to open input.dat:", err)
		return
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		enc := encodeString(line)

		fmt.Printf("// Encoded: %s\n", line)
		fmt.Printf("pub static ENC: [u16; %d] = [\n", len(enc))
		for _, val := range enc {
			fmt.Printf("    0x%04X,\n", val)
		}

		fmt.Println("];\n")
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("error reading input:", err)
	}
}
