#
# Makefile for application-based firewall for linux.
# 

CC = 	gcc
RM = 	rm -f

# source code
SRC = 	main.c \
		packetinfo.c \
		procutils.c

# link against the following libs
LIBS = 	netfilter_queue \
		nfnetlink

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

# evaluate DEBUG_MODE switch and set CFLAGS appropriately
ifeq ($(DEBUG_MODE),1)
	ALL_CFLAGS = $(CFLAGS) \
		$(addprefix -I, $(INCDIRS)) \
		$(addprefix -D, $(DEFINES))	\
		-DDEBUG -O0 -g
else
	ALL_CFLAGS = $(CFLAGS) \
		$(addprefix -I, $(INCDIRS)) \
		$(addprefix -D, $(DEFINES)) \
		-O2 -fomit-frame-pointer
endif

# add libraries to LDFLAGS
ALL_LDFLAGS = $(LDFLAGS) \
	$(addprefix -L, $(LIBDIRS)) \
	$(addprefix -l, $(LIBS))

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

