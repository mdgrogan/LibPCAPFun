CC = gcc
CFLAGS = -c -Wall
LDFLAGS = -lpcap
SOURCES = PacketSniffer.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = PacketSniffer

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
