package obfs

type Obfuscator interface {
	Obfuscate(in []byte, out []byte) int
	Deobfuscate(in []byte, out []byte) int
}
