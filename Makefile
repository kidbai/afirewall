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

# 

CFLAGS = -g -O0 -Wall -pedantic --std=gnu99
LDFLAGS = 
##############################################################################
BIN = firewall
ALL_CFLAGS = $(CFLAGS)
ALL_LDFLAGS = $(LDFLAGS) $(addprefix -l, $(LIBS))
OBJS = $(SRC:.c=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean almostclean
all: firewall

# generate dependencies
%.d: %.c
	$(CC) $(ALL_CFLAGS) -c -MM -MF $(patsubst %.o,%.d,$@) $<

# ...and include them
-include $(SRC:.c=.d)

# generate objects
%.o: %.c
	$(CC) $(ALL_CFLAGS) -c -o $@ $<

# link everything together
$(BIN): $(OBJS) Makefile
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

