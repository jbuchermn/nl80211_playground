CC = gcc
CFLAGS = -Wall -g -O3
INCLUDES = -I/usr/include/libnl3 -Idependencies
LFLAGS = 
LIBS = $(shell pkg-config --libs libnl-genl-3.0) -lpcap
SRCS = main.c dependencies/radiotap-library/radiotap.c

OBJS = $(SRCS:.c=.o)

# define the executable file 
MAIN = main

.PHONY: clean

all: $(MAIN)
	@echo Done

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) $(OBJS) $(MAIN)
