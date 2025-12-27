ifeq ($(KPATH),)
	KVER := $(shell uname -r)
	KPATH := /lib/modules/$(KVER)/build
endif

obj-m := drill_mod.o

all:
	gcc drill_test.c -Wall -static -o drill_test
	gcc drill_uaf_callback.c -Wall -static -o drill_uaf_callback
	gcc drill_uaf_callback_rop_smep.c  -Wall -static -o drill_uaf_callback_rop_smep
	gcc drill_uaf_callback_rop_smap.c  -Wall -static -o drill_uaf_callback_rop_smap
	gcc drill_uaf_w_msg_msg.c -Wall -static -o drill_uaf_w_msg_msg
	gcc drill_uaf_w_pipe_buffer.c -Wall -static -o drill_uaf_w_pipe_buffer
	gcc drill_uaf_w_pte.c -Wall -static -o drill_uaf_w_pte -lrt -lpthread
	gcc drill_uaf_w_pud.c -Wall -static -o drill_uaf_w_pud -lrt -lpthread
	gcc drill_oob_w_pipe_buffer.c -Wall -static -o drill_oob_w_pipe_buffer
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_test
	rm drill_uaf_callback
	rm drill_uaf_callback_rop_smep
	rm drill_uaf_callback_rop_smap
	rm drill_uaf_w_msg_msg
	rm drill_uaf_w_pipe_buffer
	rm drill_uaf_w_pte
	rm drill_uaf_w_pud
	rm drill_oob_w_pipe_buffer
