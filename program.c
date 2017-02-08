#include <stdlib.h>		// malloc(..) func	
#include <stdio.h> 		// fopen(..) func, fprintf(..) func
#include <time.h>		// time func's
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>	//close
#include <netinet/in.h>   //sockaddr_in (internet socket address)


void sniffPacket(unsigned char *, int );
FILE *logfile;
int dae_sock;
int length;
char ip_addr[12];
char iface[4];
char default_iface[] = "eth0";
char *curr_time;

struct sockaddr_in source_addr, dest_addr;

char *get_time(){
	time_t rawtime;
	struct tm *tm_info;
	time( &rawtime );
	tm_info = localtime( &rawtime );
	curr_time = asctime( tm_info );
	return(curr_time);
}

void sniffer_start(){
	logfile = fopen(daelog.txt,"a+");
  	if(logfile==NULL){printf(%s\n, "Unable to add records to file daelog.txt. If file not exist you need to create it @home_dir.");};
	char *moment[80];
	moment = get_time();
	fprintf(logfile,"Sniffer started %s\t\n ",moment);
	/*CREATE BLANK SOCKET*/
  dae_sock = socket(AF_INET,SOCK_STREAM(????)  ,  );
	if(dae_sock < 0){moment = get_time(); fprintf(logfile,"Socket error\ %s\t\n",moment);};
  int saddr_sz, data_sz;
  struct sockaddr saddr;
  struct in_addr in;
  unsigned char *sock_buff = (unsigned char *)malloc(65536);
	while(1){
      saddr_sz = sizeof(saddr);
      data_sz = recvfrom(dae_sock, sock_buff, 65536, 0, &saddr, &saddr_sz);
      if(data_sz < 0){
        printf("%s\n","Recvfrom error, failed to get packets");
        return 1;
      };
    
  }
};

void sniffer_stop(){
	if(close(dae_sock) == 0) {return 0;}
	else
	return 1;	
};

void show_ip_count(char *); 	// pas to the function link to ip adddress value stored in "ip_addr[]"
void select_iface(char *);	// pas to the function link to iface value stored in "iface[]"
void stat_iface(char *);	// pas to the function link to iface value stored in "iface[]"



int main(int argc, char *argv[]) // argv hold (1)the type of the net [eth, wlan], (2)N of the net type[0,1,2,..etc],(3) ip address
{
	if( argc < 2 ){ printf(%s\n,"Program get no arguments!"); return -1; }; // if program launched without parameters
	if(argv[1] == "start"){ void sniffer_start();}
	  else
	if(argv[1] == "stop"){ void sniffer_stop();}
	  else
	if(argv[1] == "show" && argv[3] == "count"){ ip_addr = argv[2]; void show_ip_count(char *ip_addr);}
	  else
	if(argv[1] == "select" && argv[2] == "iface"){ iface = argv[3]; void select_iface(char *iface);}
	  else
	if(argv[1] == "stat"){ iface = argv[2]; void stat_iface(char *iface);}
	exit(0);
	
	
	
	
	
	
	
	
	
	
	
	
	
}
