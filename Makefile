TARGET=dioshark dioparse
SHARK_OBJ=dio_shark.o
PARSE_OBJ=dio_parse.o rbtree.o

ifeq ($(RELEASE), 1)
CFLAGS= -O2
else
CFLAGS=-D DEBUG -g -O0
endif

all : $(TARGET)

dioshark: $(SHARK_OBJ)
	gcc -o $@ $< -pthread

dioparse: $(PARSE_OBJ)
	gcc -o $@ $^

%.o : %.c
	gcc $(CFLAGS) -c $<

clean : 
	rm -f $(SHARK_OBJ) $(PARSE_OBJ) $(TARGET)
