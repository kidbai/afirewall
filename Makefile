#
# Makefile for application-based firewall for linux.
# 

CC = 	gcc
RM = 	rm -f

# source code
SRC = 	main.c \
		packetinfo.c \
		procutils.c

# handle libraries that support PKG-CONFIG
PKG_CONFIG = 	libnetfilter_queue \
				libnfnetlink

# link against the following libs
LIBS = 

# include directories and linker search path
INCDIRS = 
LIBDIRS = 

# enable debug mode. (defines macro DEBUG, sets -O0 and -g)
DEBUG_MODE = 1

# define preprocessor macros here
DEFINES = 

# compiler and linker flags
CFLAGS = -Wall -pedantic --std=gnu99
LDFLAGS =

# target binary
BIN = firewall

##############################################################################
# Nothing to change here. Move along!
############################################################################## 

ALL_CFLAGS = $(CFLAGS) \
		$(addprefix -I, $(INCDIRS)) \
		$(addprefix -D, $(DEFINES))

# evaluate DEBUG_MODE switch and set CFLAGS appropriately
ifeq ($(DEBUG_MODE),1)
	ALL_CFLAGS += -DDEBUG -O0 -g
else
	ALL_CFLAGS += -O2 -fomit-frame-pointer
endif

# add libraries to LDFLAGS
ALL_LDFLAGS = $(LDFLAGS) \
	$(addprefix -L, $(LIBDIRS)) \
	$(LIBS)

# handle PKG-CONFIG stuff
ALL_CFLAGS += $(shell pkg-config --cflags $(PKG_CONFIG))
ALL_LDFLAGS += $(shell pkg-config --libs $(PKG_CONFIG))

# generate dependency and object file lists
OBJS = $(SRC:.c=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean almostclean
all: firewall

# generate dependencies
%.d: %.c
	$(CC) $(ALL_CFLAGS) -c -MM -MF $(patsubst %.o,%.d,$@) $<

# ...and include them
-include $(SRC:.c=.d)

# generate objects. Refresh when Makefile has changed
%.o: %.c Makefile
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# link everything together
$(BIN): $(OBJS)
	$(CC) $(ALL_CFLAGS) -o $(BIN) $(OBJS) $(ALL_LDFLAGS)

# clean everything
clean:
	$(RM) $(OBJS)
	$(RM) $(BIN)
	$(RM) *~
	$(RM) $(DEPS)

# clean everything but the target binary
almostclean:
	$(RM) $(OBJS)
	$(RM) *~
	$(RM) $(DEPS)

