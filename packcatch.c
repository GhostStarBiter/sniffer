#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>


#define MAX_IFACES 64
#define MAX_IP_SOURCES 1024

const char *workdir = "/home/green/Desktop/debug/";

// DECLARATION SECTION //
FILE *logfile;
FILE *all_ifaces;
FILE *pack_stats;
static char *default_iface;
char *curr_iface;
char *moment; 	// pointer to time at the given moment
static char *iface_arr[MAX_IFACES];
char *ip_addr;
char *src_ip_addr;
static int iface_to_stat;
static int snif_default;
int iface_to_snif;
int iface_nmbr = 0; // actual quantity of avaliable interfaces on machine (defined from interfaces.txt)
int sockfd;
int rec_result = 0;
int length;
struct sockaddr_in source;
struct in_addr income_addr;

//int rec_total;
struct packet_data {
	char *src_ip[MAX_IP_SOURCES];
	unsigned int pckts_cnt[MAX_IP_SOURCES];
	int total;
} stat_data[MAX_IFACES];


/**FUNCTIONS SECTION**/

char * get_time(){
	char *curr_time;
	time_t rawtime;
	struct tm *tm_info;
	time( &rawtime );
	tm_info = localtime( &rawtime );
	curr_time = asctime( tm_info );
	return(curr_time);
}

////////////////////////////////////
//////PRINT STATISTICS TO FILE//////
////////////////////////////////////
void statprint_to_file(){
	for(int i = 0; i < iface_nmbr; i++){
		fprintf(pack_stats, "%s\n", iface_arr[i]);
		for(int j = 0; j < stat_data[i].total; j++){
			fprintf(pack_stats, "%s \t %d \n", stat_data[i].src_ip[j], stat_data[i].pckts_cnt[j]);
		};
		fprintf(pack_stats, "%c \n", '_');
	};
} //end statprint_to_file()

/*
void daemonize(void){
		pid_t pid, sid;
		// Fork off the parent process
		pid = fork();
		if (pid < 0){ //fork() fail
			syslog(LOG_ERR, "Create first child process failure.");
			exit(EXIT_FAILURE);
		}
		if (pid > 0) // in parent process
			exit(EXIT_SUCCESS);
		// On success: The child process becomes session leader
		if ((sid = setsid()) < 0){
			syslog(LOG_ERR, "Create Session ID for daemon process failure.");
			exit(EXIT_FAILURE);
		};
		// Catch, ignore and handle signals
		signal(SIGCHLD, SIG_IGN);
		signal(SIGHUP, SIG_IGN);

		//Fork second time
		pid = fork();
		if (pid < 0){ //fork() fail
			syslog(LOG_ERR, "Create second child process failure.");
			exit(EXIT_FAILURE);
		}
		if (pid > 0) // in parent process
			exit(EXIT_SUCCESS);

		//IN SECOND CHILD PROCESS
		// Close all open file descriptors
		int x;
		for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
		{
		    close (x);
		};
		return;
}
*/

void HandlePacket(int data_size, unsigned char* socket_buff){
		++stat_data[iface_to_snif].total;
		//struct ethhdr *eth = (struct ethhdr *)socket_buff;
		struct iphdr *iph = (struct iphdr *)(socket_buff  + sizeof(struct ethhdr));
		source.sin_addr.s_addr = iph->saddr;
		src_ip_addr = inet_ntoa(source.sin_addr);
		if(stat_data[iface_to_snif].total == 1){
			stat_data[iface_to_snif].src_ip[0] = src_ip_addr;
			++stat_data[iface_to_snif].pckts_cnt[0];
			statprint_to_file();
			return;
		};
		for(int i = 0; i < (stat_data[iface_to_snif].total - 1); i++){
			if(strcmp(stat_data[iface_to_snif].src_ip[i], src_ip_addr) == 0){
				++stat_data[iface_to_snif].pckts_cnt[i];
				statprint_to_file();
				return;
			};
		};
		stat_data[iface_to_snif].src_ip[(stat_data[iface_to_snif].total - 1)] = src_ip_addr;
		++stat_data[iface_to_snif].pckts_cnt[(stat_data[iface_to_snif].total - 1)];
		statprint_to_file();
		return;
}



/////////
//START//
/////////
void start(){
	//daemonize(); // daemonizing the program
	umask(0);
	openlog ("pack", LOG_PID, LOG_DAEMON);
	/* Change the working directory */
	int chdir_res = chdir(workdir);
	if(chdir_res < 0){
		syslog(LOG_ERR, "Failed to change working directory. ");
		exit(EXIT_FAILURE);
	}
	/*TEXT FILE FOR INCOMING TRAFFIC STATISTICS*/
	pack_stats = fopen("statistics.txt", "a");
	if(pack_stats == NULL){
		syslog(LOG_DAEMON | LOG_ERR, "%s %s", "Open statistics.txt error: ", strerror(errno));
		exit(EXIT_FAILURE);
	};
	fprintf(logfile, "%s", "Logfile created. " /*get_time()*/);
	fprintf(logfile, "%s %s \n", "Daemon started. ", get_time());
	fprintf(pack_stats, "%s %s \n", "Daemon started ", get_time());
	//syslog(LOG_NOTICE, "%s %s", "Packcatch daemon started", moment);
	int s_addr_size;
	struct sockaddr s_addr;
	int proto = htons(ETH_P_ALL);

	int raw_len = strlen(curr_iface);
	//CREATION SOCKET WITH LOW-LEVEL PACKET INTERFACE(AF_PACKET) AND RAW NETWORK PROTOCOL ACCESS(SOCK_RAW)
	/*ETH_P_ALL - Ethernet Protocol ID for every packet*/
	sockfd = socket( AF_PACKET , SOCK_RAW , proto);
	int opt_result = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &curr_iface[0], raw_len - 1);
	////////////////////////////////////////////////////////////////////////////
	if((sockfd < 0) | (opt_result < 0)){
		//moment = get_time();
		syslog(LOG_DAEMON | LOG_ERR,"%s %s", "Socket error: ", strerror(errno));
		fprintf(logfile, "%s %s\n", "Socket error: ", strerror(errno));
		close(sockfd);
		exit(EXIT_FAILURE);
	};
	unsigned char *data_buff = (unsigned char *)malloc(65536); // packet buffer
	//struct packet_data stat_data[iface_nmbr];
	while(rec_result >= 0){
		s_addr_size = sizeof(s_addr);
		rec_result = recvfrom(sockfd, data_buff, 65536, 0, &s_addr, (socklen_t*) &s_addr_size);
		if(rec_result < 0){
			fprintf(logfile, "%s", "Error in recvfrom func. Can't get packet. "/*, moment = get_time()*/);
			exit(errno);
		}
		data_buff[rec_result] = '\0';
		HandlePacket(rec_result, data_buff);
	};
	if(sockfd != 0) close(sockfd);
	return;
}


////////
//STOP//
////////
void stop(){
	//char *time = get_time();
	//statprint_to_file();
	fclose(logfile);
	if(pack_stats != 0) fclose(pack_stats);
	fclose(all_ifaces);
	return;
}


/////////////////
//SHOW IP COUNT//
/////////////////
void show_ip_count(char *_ip_addr){

} // end of show_ip_count()

//////////////
//STAT IFACE//
//////////////
void stat_iface(char *stat_iface){
	/*OPEN FILE WITH INCOMING TRAFFIC STATISTICS FOR READING*/
	FILE* show_stat;
	show_stat = fopen("statistics.txt", "r");
	if(show_stat == NULL){
		syslog(LOG_ERR, "%s %s ", "Failed to open statistics.txt. ", strerror(errno));
		exit(EXIT_FAILURE);
	};
	if((strcmp(stat_iface,"all") == 0)){
		//print file statistics.txt line by line to the terminal (printf)
		ssize_t line_sz;
		size_t len;
		char *readline = NULL;
		while ((line_sz = getline(&readline, &len, show_stat)) != -1) {
			printf("%s", readline);
		}
		exit(EXIT_SUCCESS);
	}
	//char *show_iface;
	//show_iface = NULL;
	for(int i = 0; i < iface_nmbr; i++){
		if(strcmp(stat_iface, iface_arr[i]) == 0){/*show_iface = iface_arr[i];*/
			iface_to_stat = i;
			break;
		};
	};
	printf("\n %s %s \n", "Statistics for interface ", iface_arr[iface_to_stat]);
	printf("%s \t %s","Source IP", "Quantity of packets");
	ssize_t line;
	size_t line_len;
	char *file_line;
	while((line = getline(&file_line, &line_len, show_stat)) != -1){
		if(strcmp(file_line, iface_arr[iface_to_stat]) == 0){
			while(file_line[0] != '_'){
				printf("%s", file_line);
			};
		};
	}
	/*search in statistics.txt for line (show_iface) */
	/*print to terminal lines below*/
	/*till newline appears*/
	/*if newline appears first after line (show_iface)*/
	/*then no incoming packets on requested interface*/


} // end of stat_iface()





///////////////////////////////////////////////////////////////////////////
////////////////////////////*********MAIN*********/////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]){

	if(argc < 2){printf("%s\n", "Enter arguments!"); return 1;}
	//PROGRAM GET PARAMETERS! LET'S GO!//

	/*TEXT FILE FOR STORING PROGRAM WORK INFORMATION*/
	logfile = fopen("logfile.txt","a");
	if(logfile == NULL){
		syslog(LOG_DAEMON | LOG_ERR,"%s %s", "Open logfile.txt error: ", strerror(errno));
		exit(EXIT_FAILURE);
	};
	/*LIST OF COMPUTER NETWORK DEVICES*/
	/*must exist in dir with this file*/
	/*defaultly created by script*/
	/*manually created by terminal command "ls /sys/class/net >interfaces.txt" then "pwd" is dir with this file*/
	all_ifaces = fopen("interfaces.txt", "r");
	if(all_ifaces == NULL){
		syslog(LOG_ERR, "%s %s", "Open interfaces.txt error:", strerror(errno));
		exit(EXIT_FAILURE);
	};
	ssize_t read_sz = 0;
	size_t len = 0;
	char *readline = NULL;
	for(int k = 0;(read_sz = getline(&readline, &len, all_ifaces)) != -1; ++k){
		iface_arr[k] = readline;
		if(iface_arr[0] == NULL){
			syslog(LOG_ERR, "%s", "File interfaces.txt empty.");
			exit(EXIT_FAILURE);
		};
		iface_nmbr++;
		readline = NULL;
	};
	/*SET DEFAULT INTERFACE (eth0)*/
	/*on my laptop - enp1s0*/
	char e = 'e';
	for(int i = 0; i < iface_nmbr; i++){
		char first_char = *iface_arr[i];
		if(first_char == e){
			default_iface = iface_arr[i];
			snif_default = i;
			break;
		};
	};
	curr_iface = default_iface;
	iface_to_snif = snif_default;

	/*********************************/
	/**************START**************/
	if((strcmp(argv[1],"start")) == 0){
		fprintf(logfile, "%s %s \n", "START at ", get_time());
		start();
		exit(EXIT_SUCCESS);
	}
	else
		/********************************/
		/**************STOP**************/
  if((strcmp(argv[1],"stop")) == 0){
		fprintf(logfile, "%s %s \n", "STOP at ", get_time());
		stop();
		exit(EXIT_SUCCESS);
	}
  else
		/**************SHOW [IP] COUNT**************/
  if((strcmp(argv[1],"show") == 0) && (strcmp(argv[3],"count") == 0)){
		ip_addr = argv[2];
		show_ip_count(ip_addr);
	}
  else
		/*************SELECT INTERFACE*************/ //CHECK
  if((strcmp(argv[1],"select") == 0) && (strcmp(argv[2],"iface") == 0)){
		char *set_iface = argv[3];
		for(int i = 0; i < iface_nmbr; i++){
			if((strcmp(set_iface, iface_arr[i])) == 0){
				curr_iface = iface_arr[i];
				iface_to_snif = i;
				break;};
		};
		// if user try to select interface that is not in list of avaliable interfaces
		if((strcmp(set_iface, iface_arr[iface_to_snif])) != 0){
			printf("\n %s \n", "Unknown interface. See the list of avaliable intefaces in /sys/class/net.");
			printf("%s \n", "Interface to snif set to default - ethernet0.");
			curr_iface = default_iface;
			iface_to_snif = snif_default;
		};
		/*restart the daemon*/
		stop();
		sleep(1);
		start();
		exit(EXIT_SUCCESS);
		}
  else
		/************************************************/
		/***********SHOW STAT ABOUT INTERFACE************/
  if(strcmp(argv[1],"stat") == 0){
		char *iface = argv[2];
		if(iface == NULL){
			iface = "all";
		};
		stat_iface(iface);
		exit(EXIT_SUCCESS);
	}
  exit(0);
}
