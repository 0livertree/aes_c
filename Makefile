CC ?= cc

.PHONY: all


ifeq ($(OS),Windows_NT)
all: main rijndael.dll

main: rijndael.o main.c
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
	$(CC) -o rijndael.o -c rijndael.c

rijndael.dll: rijndael.o
	$(CC) -shared -o rijndael.dll rijndael.c
clean:
	del -f *.o *.so
	del -f main
	del -f *.dll
else
all: main rijndael.so

main: rijndael.o main.c
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o

clean:
	rm -f *.o *.so
	rm -f main
endif