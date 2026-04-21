obj-m += monitor.o

KDIR := /lib/modules/$(shell uname -r)/build

# Using CURDIR is more reliable for the kernel build system
USER_TARGETS := engine memory_hog cpu_hog io_pulse

# Default target
all: $(USER_TARGETS) monitor.ko

engine: engine.c monitor_ioctl.h
	gcc -O2 -Wall -Wextra -o engine engine.c -lpthread

memory_hog: memory_hog.c
	gcc -O2 -Wall -static -o memory_hog memory_hog.c

cpu_hog: cpu_hog.c
	gcc -O2 -Wall -static -o cpu_hog cpu_hog.c

io_pulse: io_pulse.c
	gcc -O2 -Wall -static -o io_pulse io_pulse.c

# M=$(CURDIR) ensures the path is passed correctly without extra spaces
monitor.ko: monitor.c monitor_ioctl.h
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	rm -f $(USER_TARGETS) *.o *.ko *.mod.c *.symvers *.order
	rm -rf logs
	rm -f /tmp/mini_runtime.sock

.PHONY: all clean
