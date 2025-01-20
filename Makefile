KVER = $(shell uname -r)
KPATH := /lib/modules/$(KVER)/build

obj-m := drill_mod.o

all:
	gcc drill_exploit_uaf_callback.c -static -o drill_exploit_uaf_callback
	gcc drill_test.c -static -o drill_test
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_exploit_uaf_callback drill_test
