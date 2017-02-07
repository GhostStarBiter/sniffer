#include <stdlib.h>		// malloc(..) func	
#include <stdio.h> 		// fopen(..) func, fprintf(..) func
#include <time.h>		// time func's
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>   //sockaddr_in (internet socket address)


void sniffPacket(unsigned char *, int );
FILE *logfile;
int dae_sock;
int length;
struct sockaddr_in source_addr, dest_addr;
char *get_time(){
	time_t rawtime;
	struct tm *tm_info;
	time( &rawtime );
	tm_info = localtime( &rawtime );
	curr_time = asctime( tm_info );
	return( &curr_time );
}



int main(int argc, char *argv[]) // argv hold (1)the type of the net [eth, wlan], (2)N of the net type[0,1,2,..etc],(3) ip address
{
	if( argc < 2 ){ printf(%s\n,"Program get no arguments!"); return -1; }; // if program launched without parameters
  	if(argc == 2 && argv[argc] == "start"){ 
/*=begin=*/
	logfile = fopen(daelog.txt,"a+");
  	if(logfile==NULL){printf(%s\n, "Unable to add records to file daelog.txt. If file not exist you need to create it @home_dir.");};
	char *moment[80];
	moment = get_time();
	fprintf(logfile,"Sniffer started %s\t\n ",moment);
	/*CREATE BLANK SOCKET*/
  	dae_sock = socket(AF_INET,SOCK_STREAM(????)  ,  );
	if(dae_sock < 0){printf};
}
