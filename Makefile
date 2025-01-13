KVER = $(shell uname -r)
KPATH := /lib/modules/$(KVER)/build

obj-m := drill_mod.o

all:
	gcc drill_exploit_uaf_callback.c -static -o drill_exploit_uaf_callback
	gcc drill_exploit_nullderef.c -static -o drill_exploit_nullderef
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_exploit_uaf_callback drill_exploit_nullderef
