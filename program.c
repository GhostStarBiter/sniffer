#include <stdlib.h>		// malloc(..) func	
#include <stdio.h> 		// fopen(..) func
#inclide <time.h>		// time func's
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>   //sockaddr_in (internet socket address)

FILE *logfile;
int daemon_socket;
int length;
struct sockaddr_in source_addr, dest_addr; // declaration of the internet socket





int main(int argc, char *argv[]) // argv hold (1)the type of the net [eth, wlan], (2)N of the net type[0,1,2,..etc],(3) ip address
{
  if(argc<2) return 1;
  
  daemon_socket = socket(AF_INET,SOCK_STREAM(????)  ,  );
}
