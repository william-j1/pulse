
CC = gcc
CFLAGS = -Wall -Wextra -I.
SOURCES = server.c lin.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = server
all: $(EXECUTABLE)
$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $^
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
.PHONY: all clean
