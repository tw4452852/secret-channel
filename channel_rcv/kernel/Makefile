obj-m:=channel.o
default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build/ M=$(shell pwd) modules 

clean:
	rm -fr modules*
	rm -fr Module*
	rm -fr *.*o
	rm -fr *.mod.*
