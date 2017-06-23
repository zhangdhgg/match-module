obj-m +=match_ip.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd`
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean

install:
	sudo /sbin/insmod match_ip.ko
remove:
	sudo /sbin/rmmod match_ip
