CFLAGS ?= -O2 -g -Wall -Werror
CFLAGS += -std=gnu99
CPPFLAGS += -D_GNU_SOURCE -D__CHECK_ENDIAN__

OBJS := sed.o argconfig.o suffix.o plugin.o

default: sed-opal

sed-opal: main.c $(OBJS)
	  $(CC) $(CPPFLAGS) $(CFLAGS) main.c -o sed-opal $(OBJS)

clean:
	$(RM) *.o
