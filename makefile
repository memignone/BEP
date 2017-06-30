CFLAGS = gcc -g -c
HDRSPATH = Headers/
OBJSPATH = Objects/
SRCSPATH = Sources/
HFLAGS = -I $(HDRSPATH)
LIBS = 
HDRS = clefia.h helper_functions.h
OBJS = clefia.o helper_functions.o main.o
HDRSRPL = $(patsubst %.h, $(HDRSPATH)%.h, $(HDRS))
OBJSRPL = $(patsubst %.o, $(OBJSPATH)%.o, $(OBJS))

all: clean main

main: $(OBJSRPL)
		gcc -o main $(OBJSRPL) $(LIBS)

$(OBJSPATH)%.o: $(SRCSPATH)%.c $(HDRSRPL)
				$(CFLAGS) $< -o $@ $(HFLAGS)

clean: 
	   rm -f main $(OBJSPATH)*.o $(SRCSPATH)*~ $(HDRSPATH)*~
