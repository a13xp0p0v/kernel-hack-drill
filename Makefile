KVER = $(shell uname -r)
KPATH := /lib/modules/$(KVER)/build

obj-m := drill_mod.o

all:
	gcc drill_test.c -Wall -static -o drill_test
	gcc drill_uaf_callback.c -Wall -static -o drill_uaf_callback
	gcc drill_uaf_write_msg_msg.c -Wall -static -o drill_uaf_write_msg_msg
	gcc drill_uaf_write_pipe_buffer.c -Wall -static -o drill_uaf_write_pipe_buffer
	make -C $(KPATH) M=$(PWD) modules

clean:
	make -C $(KPATH) M=$(PWD) clean
	rm drill_uaf_callback drill_uaf_write_msg_msg drill_uaf_write_pipe_buffer drill_test
