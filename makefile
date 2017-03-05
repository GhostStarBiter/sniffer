CMP = gcc
FLAGS = -std=c99 -g -Os -Wall -pedantic-errors -o


all:
	$(CMP) $(FLAGS) pack pack.c

clean:
	-rm pack
