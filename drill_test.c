/*
 * This is a test for drill_mod.ko.
 * Please run it with CONFIG_KASAN=y, it should not crash the kernel.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "drill.h"

int act(int fd, int code, int n, char *args)
{
	char buf[DRILL_ACT_SIZE] = { 0 };
	size_t len = 0;
	ssize_t bytes = 0;

	if (args)
		snprintf(buf, DRILL_ACT_SIZE, "%d %d %s", code, n, args);
	else
		snprintf(buf, DRILL_ACT_SIZE, "%d %d", code, n);

	len = strlen(buf) + 1; /* with null byte */
	assert(len <= DRILL_ACT_SIZE);
	printf("    going to write \"%s\" (%zu bytes) to drill_act\n", buf, len);

	bytes = write(fd, buf, len);
	if (bytes <= 0) {
		perror("[-] write");
		return EXIT_FAILURE;
	}
	if (bytes != len) {
		printf("[-] wrote only %zd bytes to drill_act\n", bytes);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_FAILURE;
	int fd = -1;
	int item_n = 42;
	ssize_t bytes = 0;
	char *err_act = NULL;

	fd = open("/proc/drill_act", O_WRONLY);
	if (fd < 0) {
		perror("[-] open drill_act");
		goto end;
	}
	printf("[+] drill_act is opened\n");

	printf("[?] test normal functionality of drill.ko...\n");

	printf("test DRILL_ACT_ALLOC\n");
	ret = act(fd, DRILL_ACT_ALLOC, item_n, NULL);
	if (ret == EXIT_FAILURE)
		goto end;

	printf("test DRILL_ACT_CALLBACK\n");
	ret = act(fd, DRILL_ACT_CALLBACK, item_n, NULL);
	if (ret == EXIT_FAILURE)
		goto end;

	printf("test DRILL_ACT_SAVE_VAL\n");
	ret = act(fd, DRILL_ACT_SAVE_VAL, item_n, "0xa5a5a5a541414141 64");
	if (ret == EXIT_FAILURE)
		goto end;

	printf("test DRILL_ACT_CALLBACK\n");
	ret = act(fd, DRILL_ACT_CALLBACK, item_n, NULL);
	if (ret == EXIT_FAILURE)
		goto end;

	printf("test DRILL_ACT_FREE\n");
	ret = act(fd, DRILL_ACT_FREE, item_n, NULL);
	if (ret == EXIT_FAILURE)
		goto end;

	printf("[+] looks like normal functionality in drill.ko works fine\n");

	printf("\n[?] test error handling in drill.ko\n");

	printf("writing zero bytes\n");
	bytes = write(fd, "", 0);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	printf("writing empty string\n");
	bytes = write(fd, "", 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "x";
	printf("using bad drill act: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "1";
	printf("using drill act without item number: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "1 wat";
	printf("using bad item number: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "100 5";
	printf("using non-existing drill act: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "1 1000000";
	printf("using big item number: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "3 50";
	printf("using DRILL_ACT_SAVE_VAL without value: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "3 50 88";
	printf("using DRILL_ACT_SAVE_VAL without offset: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "3 50 wat 16";
	printf("using DRILL_ACT_SAVE_VAL with bad value: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "3 50 0x55 wat";
	printf("using DRILL_ACT_SAVE_VAL with bad offset: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	err_act = "3 50 0x55 0xffffffffffff";
	printf("using DRILL_ACT_SAVE_VAL with huge offset: %s\n", err_act);
	bytes = write(fd, err_act, strlen(err_act) + 1);
	if (bytes >= 0) {
		ret = EXIT_FAILURE;
		goto end;
	}

	printf("[+] looks like error handling in drill.ko works fine\n");

end:
	if (ret == EXIT_FAILURE)
		printf("\n[-] test failed!\n");
	else
		printf("\n[+] the end! By the way, did you run it with CONFIG_KASAN=y?\n");

	if (fd >= 0) {
		ret = close(fd);
		if (ret != 0)
			perror("[-] close fd");
	}

	return ret;
}
