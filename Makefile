ifeq ($(KPATH),)
	KVER := $(shell uname -r)
	KPATH := /lib/modules/$(KVER)/build
endif

obj-m := drill_mod.o

all:
	gcc drill_test.c -Wall -static -o drill_test
	gcc drill_uaf_callback.c -Wall -static -o drill_uaf_callback
	gcc drill_uaf_w_msg_msg.c -Wall -static -o drill_uaf_w_msg_msg
	gcc drill_uaf_w_pipe_buffer.c -Wall -static -o drill_uaf_w_pipe_buffer
	gcc drill_uaf_w_pte.c -Wall -static -o drill_uaf_w_pte
	gcc drill_uaf_w_pud.c -Wall -static -o drill_uaf_w_pud
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_test drill_uaf_callback drill_uaf_w_msg_msg drill_uaf_w_pipe_buffer drill_uaf_w_pte drill_uaf_w_pud
