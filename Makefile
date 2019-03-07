KVER = $(shell uname -r)
KPATH := /lib/modules/$(KVER)/build

obj-m := drill_mod.o

all: drill_exploit_uaf
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_exploit_uaf
