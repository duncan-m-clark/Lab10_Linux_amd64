default: all

labcrackme: LabCrackme.c
	gcc -03 -o $@ $< -lcrypto
	strip $@

dbg_labcrackme: LabCrackme.c
	gcc -D_DEBUG -01 -g -o $@ $< -lcrypto

all: labcrackme dbg_labcrackme