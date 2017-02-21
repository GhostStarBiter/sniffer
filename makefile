CMP = gcc
FLAGS = -std=c99 -g -Os -Wall -pedantic-errors -o


all:
	$(CMP) $(FLAGS) pack packcatch.c &>errlog.txt

clean:
	-rm pack
	-rm errlog.txt
	-rm statistics.txt
	-rm logfile.txt
