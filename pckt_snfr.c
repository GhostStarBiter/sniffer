#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

FILE *tmp_log;
FILE *all_ifaces;
FILE *stat;
char *default_iface;
char *curr_iface;
char iface1[];
char iface2[];
char iface3[];
char *moment; 	// pointer to time at the given moment
char *iface;
char *ip_addr;
int i, j, k, p, q, n, g, v, d, f, s;
int raw_sock;
int length;
struct sockaddr_in source;
struct in_addr income_addr;
int result;
int rec_total;
struct snif_data {unsigned long src_ip[65563]; unsigned int pckts_cnt[65563]; int total;} stat_data[3];

char * get_time(){
	char *curr_time;
	time_t rawtime;
	struct tm *tm_info;
	time( &rawtime );
	tm_info = localtime( &rawtime );
	curr_time = asctime( tm_info );
	return(curr_time);
}

void HandlePacket(int data_size, unsigned char* socket_buff){
		++rec_total;
		if(!(strcmp(curr_iface, iface1))){ f = 0;}
		else
		if(!(strcmp(curr_iface, iface2))){ f = 1;}
		else
		if(!(strcmp(curr_iface, iface3))){ f = 2;}
		struct ethhdr *eth = (struct ethhdr *)socket_buff;
		struct iphdr *iph = (struct iphdr *)(socket_buff  + sizeof(struct ethhdr));
		uint32_t src_ip_addr = iph->saddr;
		if(!(strcmp(curr_iface, iface1))){ f = 0;}
		else
		if(!(strcmp(curr_iface, iface2))){ f = 1;}
		else
		if(!(strcmp(curr_iface, iface3))){ f = 2;}
		++stat_data[f].total;
		if(stat_data[f].total == 1){ stat_data[f].src_ip[0] = src_ip_addr; ++stat_data[f].pckts_cnt[0];}
		for(k = 1; k < stat_data[f].total; k++){
			if(stat_data[f].src_ip[k] == src_ip_addr){++stat_data[f].pckts_cnt[k];}
			else
			if(stat_data[f].src_ip[k] != src_ip_addr){stat_data[f].src_ip[k] = src_ip_addr; ++stat_data[f].pckts_cnt[k];}
		};
		stat_data[f].src_ip[stat_data[f].total] = '\0';
		stat_data[f].pckts_cnt[stat_data[f].total] = '\0';
		return;
}

////////////////////////////////////
//////PRINT STATISTICS TO FILE//////
////////////////////////////////////
void statprint_to_file(void){
	moment = get_time();
	fprintf(stat, "%s\n", moment);
	fprintf(stat, "%s\n", "Interface");
	fprintf(stat, "%s\n", iface1);
	if(stat_data[0].total == 0){
		fprintf(stat, "%s\n", "Get nothing.");
	}
	else
	if(stat_data[0].total > 0){
		fprintf(stat, "%s\n", "IP address");
		for(g = 0; g < stat_data[0].total; g++){
			struct in_addr tmp0;
			tmp0.s_addr = stat_data[0].src_ip[g];
			source.sin_addr = tmp0;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			fprintf(stat, "%s \t %d \n", tmp_str_ip, stat_data[0].pckts_cnt[g]);
		};
	};
	fprintf(stat, "\n\n");
	fprintf(stat, "%s\n", iface2);
	if(stat_data[1].total == 0){
		fprintf(stat, "%s\n", "Get nothing.");
	}
	else
	if(stat_data[1].total > 0){
		fprintf(stat, "%s\n", "IP address");
		for(v = 0; v < stat_data[1].total; v++){
			struct in_addr tmp1;
			tmp1.s_addr = stat_data[0].src_ip[g];
			source.sin_addr = tmp1;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			fprintf(stat, "%s \t %d \n", tmp_str_ip, stat_data[1].pckts_cnt[v]);
		};
	};
	fprintf(stat, "\n\n");
	fprintf(stat, "%s\n", iface3);
	if(stat_data[2].total == 0){
		fprintf(stat, "%s\n", "Get nothing.");
	}
	else
	if(stat_data[2].total > 0){
		fprintf(stat, "%s\n", "IP address");
		for(d = 0; d < stat_data[2].total; d++){
			struct in_addr tmp2;
			tmp2.s_addr = stat_data[0].src_ip[g];
			source.sin_addr = tmp2;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			fprintf(stat, "%s \t %d \n", tmp_str_ip, stat_data[2].pckts_cnt[d]);
		};
	};
}

/////////
//START//
/////////
void start(){
	int sock_addr_size;
	int rec_result = 0;
	struct sockaddr_storage sock_addr;
	//CREATION SOCKET WITH LOW-LEVEL PACKET INTERFACE(AF_PACKET) AND RAW NETWORK PROTOCOL ACCESS(SOCK_RAW)
	/*ETH_P_ALL - Ethernet Protocol ID for every packet*/
	raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	setsockopt(raw_sock, SOL_SOCKET, SO_BINDTODEVICE, curr_iface, strlen(curr_iface));
	////////////////////////////////////////////////////////////////////////////
	if(raw_sock < 0){
		moment = get_time();
		fprintf(tmp_log, "%s %s %s\n", moment, "Socket error ", strerror(errno));
		exit(errno);
	};
  printf("%s \t %s \n","Start sniffer", moment = get_time());
	unsigned char *data_buff = (unsigned char *)malloc(65536); // packet buffer
	while(rec_result >= 0){
		sock_addr_size = sizeof(sock_addr);
		rec_result = recvfrom(raw_sock, data_buff, 65536, 0, (struct sockaddr *) &sock_addr, (socklen_t *) sock_addr_size);
		if(rec_result < 0){
			fprintf(tmp_log, "%s %s", "Error in recvfrom func. Can't get packet. ", moment = get_time());
			exit(errno);
		}
		data_buff[rec_result] = '\0';
		HandlePacket(rec_result, data_buff);
	};
	return;
}

////////
//STOP//
////////
void stop(){
	statprint_to_file();
	close(raw_sock);
  char *time = get_time();
  printf("%s \t %s \n","Stop sniffer",time);
	exit(0);
}

/////////////////
//SHOW IP COUNT//
/////////////////
void show_ip_count(char *_ip_addr){
	int i, k, t;
	int done = 0;
	if(stat_data[0].total > 0){
		for(i = 0; i < stat_data[0].total; i++){
			struct in_addr tmp0;
			tmp0.s_addr = stat_data[0].src_ip[i];
			source.sin_addr = tmp0;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			if(strcmp(tmp_str_ip, _ip_addr) == 0){
				printf("\t %s \t %s \n", "Interface: ", iface1);
				printf("\t %s \t %s \n", "Requested IP:", _ip_addr);
				printf("\t %s \t %d \n", "Packets quantity: ", stat_data[0].pckts_cnt[i]);
				done = 1;
			};
		};
	}
	else
	if(stat_data[1].total > 0){
		for(k = 0; k < stat_data[1].total; k++){
			struct in_addr tmp1;
			tmp1.s_addr = stat_data[1].src_ip[k];
			source.sin_addr = tmp1;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			if(strcmp(tmp_str_ip, _ip_addr) == 0){
				printf("\t %s \t %s \n", "Interface: ", iface2);
				printf("\t %s \t %s \n", "Requested IP:", _ip_addr);
				printf("\t %s \t %d \n", "Packets quantity: ", stat_data[1].pckts_cnt[k]);
				done = 1;
			};
		};
	}
	else
	if(stat_data[2].total > 0){
		for(t = 0; t < stat_data[2].total; t++){
			struct in_addr tmp2;
			tmp2.s_addr = stat_data[2].src_ip[t];
			source.sin_addr = tmp2;
			char *tmp_str_ip = inet_ntoa(source.sin_addr);
			if(strcmp(tmp_str_ip, _ip_addr) == 0){
				printf("\t %s \t %s \n", "Interface: ", iface3);
				printf("\t %s \t %s \n", "Requested IP:", _ip_addr);
				printf("\t %s \t %d \n", "Packets quantity: ", stat_data[2].pckts_cnt[t]);
				done = 1;
			};
		};
	}
	else
	if(done == 0){
		printf("\n %s \n", "IP not found.");
	};
	return;
} // end of show_ip_count()

//////////////
//STAT IFACE//
//////////////
void stat_iface(char *stat_iface){
	s = 5;
	if(strcmp(stat_iface, iface1) == 0){ s = 0;}
	else
	if(strcmp(stat_iface, iface2) == 0){ s = 1;}
	else
	if(strcmp(stat_iface, iface3) == 0){ s = 2;}
	else
	if(stat_iface == (NULL)){ s = 4; };
	if( s < 3 ){
		printf("\n %s %s \n", "Statistics for interface ", stat_iface);
		printf("%s \t %s","Source IP", "Quantity of packets");
		int e;
		for(e = 0; e < stat_data[s].total; e++){
			printf("%d \t %d \n", stat_data[s].src_ip[e], stat_data[s].pckts_cnt[e]);
		};
	}
	else
	if( s == 4 ){
		int u;
		for(u = 0; u < 3; u++){
			if(u == 0){
				printf("\n %s %s \n", "Statistics for interface ", iface1);
				printf("%s \t %s","Source IP", "Quantity of packets");
				int x;
				for(x = 0; x < stat_data[u].total; x++){
					printf("%d \t %d \n", stat_data[u].src_ip[x], stat_data[u].pckts_cnt[x]);
				};
			}
			else
			if(u == 1){
				printf("\n %s %s \n", "Statistics for interface ", iface2);
				printf("%s \t %s","Source IP", "Quantity of packets");
				int y;
				for(y = 0; y < stat_data[u].total; y++){
					printf("%d \t %d \n", stat_data[u].src_ip[y], stat_data[u].pckts_cnt[y]);
				};
			}
			else
			if(u == 2){
				printf("\n %s %s \n", "Statistics for interface ", iface3);
				printf("%s \t %s","Source IP", "Quantity of packets");
				int z;
				for(z = 0; z < stat_data[u].total; z++){
					printf("%d \t %d \n", stat_data[u].src_ip[z], stat_data[u].pckts_cnt[z]);
				};
			};
		};
	};
} // end of stat_iface()
///////////////////////////////////////////////////////////////////////////
////////////////////////////*********MAIN*********/////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
	if(argc < 2){printf("%s\n", "Enter arguments!"); return 1;}
	//PROGRAM GET PARAMETERS! LET'S GO!//
	tmp_log = fopen("logfile.txt","a");
	moment = get_time();
	fprintf(tmp_log, "%s %s", "Program get parameters at time ", moment);

/*******************FIGURE OUT WHAT PARAMETER(S) RECIEVED*******************/
// for getting interface name used command ifconfig.
	all_ifaces = fopen("interfaces.txt", "r");
	stat = fopen("statistics.txt", "a");
	char ch_buff[100];
	fread(ch_buff, sizeof(char), 100, all_ifaces);
	char *esc1_ptr = strchr(ch_buff, '\n');
	char *esc2_ptr = strchr(ch_buff[(int) (esc1_ptr+1)], '\n');
	char *esc3_ptr = strchr(ch_buff[(int) (esc2_ptr+1)], '\n');
	char iface1[(int)esc1_ptr];
	char iface2[(int) (esc2_ptr - esc1_ptr)];
	char iface3[(int) (esc3_ptr - esc2_ptr)];
	for(p = 0; p < (int)esc1_ptr; p++){
		iface1[p] = ch_buff[p];
	};
	for(q = 0; q < (int)(esc2_ptr - esc1_ptr); q++){
		iface2[q] = ch_buff[(int) (esc1_ptr + 1 + q)];
	};
	for(n = 0; n < (int)(esc3_ptr - esc2_ptr); n++){
		iface3[n] = ch_buff[(int) (esc2_ptr + 1 + n)];
	};
	if(iface1[0] == 'e'){default_iface = iface1;}
	else
	if(iface2[0] = 'e'){default_iface = iface2;}
	else
	if(iface3[0] == 'e'){default_iface = iface3;};
		/**************START**************/
  if(strcmp(argv[1],"start") == 0){
		start();
		fprintf(tmp_log, "%s %s\n", "Parameters are: ", argv[1]);
		//fprintf(tmp_log, "%s \n", " ");
	}
    else
		/**************STOP**************/
  if(strcmp(argv[1],"stop") == 0){
		stop();
		fprintf(tmp_log, "%s %s\n", "Parameters are: ", argv[1]);
		//fprintf(tmp_log, "%s \n", " ");
	}
    else
		/**************SHOW [IP] COUNT**************/
  if((strcmp(argv[1],"show") == 0) && (strcmp(argv[3],"count") == 0)){
		ip_addr = argv[2];
		show_ip_count(ip_addr);
		fprintf(tmp_log, "%s %s %s %s \n", "Parameters are: ", argv[1], argv[2], argv[3]);
		//fprintf(tmp_log, "%s \n", " ");
	}
    else
		/*************SELECT INTERFACE*************/
  if((strcmp(argv[1],"select") == 0) && (strcmp(argv[2],"iface") == 0)){
		char *set_iface = argv[3];
		if(!(strcmp(set_iface, iface1)) | !(strcmp(set_iface, iface2)) | !(strcmp(set_iface,iface3))){
			curr_iface = set_iface;
			start();
		}
		else
		curr_iface = default_iface;
		printf("%s", "Unknown interface. Type ls /sys/class/net for info.");
		printf("%s %s", "Default interface (Ethernet 0) is set: ", default_iface);
		if(argv[3] == NULL){
			argv[3] = "Ethernet 0 (default)";
			curr_iface = default_iface;
		};

		fprintf(tmp_log, "%s %s %s %s \n", "Parameters are: ", argv[1], argv[2], argv[3]);
		//fprintf(tmp_log, "%s \n", " ");
	}
    else
		/***********************SHOW STAT ABOUT INTERFACE*********************/
  if(strcmp(argv[1],"stat") == 0){
		iface = argv[2];
		stat_iface(iface);
		fprintf(tmp_log, "%s %s %s \n", "Parameters are: ", argv[1], argv[2]);
		//fprintf(tmp_log, "%s \n", " ");
	}
	fprintf(tmp_log, "%s \n", " ");
	fclose(tmp_log);
  exit(0);
}
