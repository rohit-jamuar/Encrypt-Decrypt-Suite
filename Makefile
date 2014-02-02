all: techrypt techdec

techrypt: techrypt.c
	gcc -o techrypt techrypt.c `libgcrypt-config --cflags --libs`

techdec: techdec.c
	gcc -o techdec techdec.c `libgcrypt-config --cflags --libs`
