/*		HOWTO:
*	1. Copy files "makefile" and "pack.c" on your computer hard disk. 
*	2. Run terminal in directory with copied files. 
*	3. Type to terminal "make" command to compile the pack.c file and get executable file "pack".
*	4. Type to terminal command "sudo chown root.root pack" to run program as root user.
*	5. Change file permissions. Type to terminal "sudo chmod 4755 pack".
*	6. Make symbolic link "sudo ln -s $(pwd)/pack /usr/local/bin/pack_d.
*		P.S. here $(pwd) means absolute path to directory with file "pack"
*		P.P.S. pack_d - program's command line name. Chose any name that contains word "pack".
*	7. Type "pack_d"(or how you called your packet sniffer) to terminal and hit enter to see program options.
*/

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#define MAX_IFACES 64
#define MAX_IP_SOURCES 65536


// DECLARATION SECTION //
pid_t ch_pid;

FILE *_logfile;
FILE *_all_ifaces;
FILE *_pack_stats;
FILE *_tmp_stat;
static char *_default_iface;
char *_curr_iface;
static char *_iface_arr[MAX_IFACES];
char *_ip_addr;
char *_argv = " ";
int iface_to_stat;
int snif_default;
int iface_to_snif;
int iface_nmbr;
int sockfd;
int rec_result = 0;
int raw_len;

time_t daemon_start;

#define BUFSIZE 65536UL

static struct packet_data {
    char* src_ip[MAX_IP_SOURCES];
    int pckts_cnt[MAX_IP_SOURCES];
    double pckts_time[MAX_IP_SOURCES];
    int total;
} iface_stat_data;

/**FUNCTIONS SECTION**/

char * GetTime(){
    char *_curr_time;
    time_t rawtime;
    struct tm *tm_info;
    time( &rawtime );
    tm_info = localtime( &rawtime );
    _curr_time = asctime( tm_info );
    int str_sz = strlen(_curr_time);
    _curr_time[str_sz - 1] = '\0';
    return(_curr_time);
}

////////////////////////////////////
//////PRINT STATISTICS TO FILE//////
////////////////////////////////////

void TempStatToFile(struct packet_data iface_stat_data){
    if((_tmp_stat = fopen("tmp_stat.txt", "w")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR, "%s%s", "Open tmp_stat.txt error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    fprintf(_tmp_stat, "%s %s%d\n", _iface_arr[iface_to_snif], "| Interface total packet quantity: ",iface_stat_data.total);
    fprintf(_tmp_stat, "%s\n", "   IP address   |  Packets quantity  in  sec from start");
    for(int j = 0; iface_stat_data.src_ip[j] != NULL; j++) {
        fprintf(_tmp_stat, "%s\t|\t%d pcs in\t%5.0f s\n", iface_stat_data.src_ip[j], iface_stat_data.pckts_cnt[j], iface_stat_data.pckts_time[j]);
    };
    time_t t_run;
    double runtime;
    time(&t_run);
    runtime = difftime( t_run, daemon_start );
    fprintf(_tmp_stat, "%s Runtime: %5.0f s\n", "***********************", runtime);
    fprintf(_tmp_stat, "%s\n", "--------------------------------------");
    fclose(_tmp_stat);
    return;
} 

struct packet_data ProcessIP(char* _ip_address, struct packet_data iface_stat_data){
    int ip_found = 0;
    int vacant = 0;
    int cmp_res;

    double time_diff;

    for(int i = 0; i < MAX_IP_SOURCES; i++){
        if(iface_stat_data.src_ip[i] == NULL){
            break;
        };
        cmp_res = !(strcmp( iface_stat_data.src_ip[i], (const char*) _ip_address ));
        vacant = i + 1;
        if(cmp_res){
            iface_stat_data.pckts_cnt[i]++;
            time_t packet_time;
            time(&packet_time);
            time_diff = difftime(packet_time, daemon_start);
            iface_stat_data.pckts_time[i] = time_diff;
            ip_found = 1;
            break;
        };
    };
    if(!ip_found){
        iface_stat_data.src_ip[vacant] = _ip_address;
        iface_stat_data.pckts_cnt[vacant]++;
        time_t packet_time;
        time(&packet_time);
        time_diff = difftime(packet_time, daemon_start);
        iface_stat_data.pckts_time[vacant] = time_diff;
    };
    TempStatToFile(iface_stat_data);
    return iface_stat_data;
}

struct packet_data HandlePacket(unsigned char* socket_buff, struct packet_data iface_stat_data){
    iface_stat_data.total++;
    //struct ethhdr *eth = (struct ethhdr *)socket_buff;
    struct iphdr* iph = (struct iphdr *)(socket_buff  + sizeof(struct ethhdr));
    struct sockaddr_in source;
    source.sin_addr.s_addr = iph->saddr;
    char* _income_ip_addr = (char*) malloc(sizeof(char)*16);
    char* s_ip_addr = inet_ntoa(source.sin_addr);
    for(int i = 0; s_ip_addr[i] != '\0'; i++){
        _income_ip_addr[i] = s_ip_addr[i];
        _income_ip_addr[i+1] = '\0';
    };

    iface_stat_data = ProcessIP(_income_ip_addr, iface_stat_data);
    _income_ip_addr = NULL;
    return iface_stat_data;
}


void Daemonize(void){
	pid_t sid;
	// Fork off the parent process
	ch_pid = fork();
	if (ch_pid < 0){ //fork() fail
		syslog(LOG_ERR, "Create first child process failure.");
		exit(EXIT_FAILURE);
	}
	if (ch_pid > 0) // in parent process
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
	ch_pid = fork();
	if (ch_pid < 0){ //fork() fail
		syslog(LOG_ERR, "Create second child process failure.");
		exit(EXIT_FAILURE);
	}
	if (ch_pid > 0) // in parent process
		return;

	//IN SECOND CHILD PROCESS
	// Close all open file descriptors
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
	    close (x);
	};
	return;
}


/////////
//START//
/////////
void Start(){
    int par_pid = getpid();
    /* daemonizing the program */
    Daemonize();
    
    if(ch_pid > par_pid){
	return;
    };
    time(&daemon_start);
    umask(0);
    openlog ("packcatch", LOG_PID, LOG_DAEMON);

    syslog(LOG_NOTICE, "%s %s \n", "packcatch daemon started", GetTime());

    /*Start-time to statistics file*/
    if((_pack_stats = fopen("statistics.txt", "a")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR, "%s %s \n", "Open statistics.txt error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    fprintf(_pack_stats, "%s %s %s\n", GetTime(), "start", _curr_iface);
    fclose(_pack_stats);
    /* LOG */
    if((_logfile = fopen("logfile.txt","a")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    fprintf(_logfile, "%s\t%s %s\n", GetTime(),"start", _curr_iface);
    fclose(_logfile);

    long s_addr_size;
    struct sockaddr s_addr;
    int proto = htons(ETH_P_ALL);
    raw_len = strlen(_curr_iface);

    //CREATION SOCKET WITH LOW-LEVEL PACKET INTERFACE(AF_PACKET) AND RAW NETWORK PROTOCOL ACCESS(SOCK_RAW)
    /*ETH_P_ALL - Ethernet Protocol ID for every packet*/
    sockfd = socket( AF_PACKET , SOCK_RAW , proto);
    int opt_result = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, _curr_iface, raw_len);

    if((sockfd < 0) || (opt_result < 0)){
        syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Socket error: ", strerror(errno));
        if((_logfile = fopen("logfile.txt","a")) == NULL){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(_logfile, "\t\t\t%s%s\n", "Socket error:", strerror(errno));
        fclose(_logfile);
    };

    unsigned char* data_buff = (unsigned char*) malloc(BUFSIZE); // packet buffer
    while(rec_result >= 0){
        s_addr_size = sizeof(s_addr);
        rec_result = recvfrom(sockfd, data_buff, 65536, 0, &s_addr, (socklen_t*) &s_addr_size);
        if(rec_result < 0){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Error in recvfrom function: ", strerror(errno));
            if((_logfile = fopen("logfile.txt","a")) == NULL){
                syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
                exit(EXIT_FAILURE);
            };
            fprintf(_logfile, "%s\t%s%s\n", GetTime(), "Error in recvfrom function: ", strerror(errno));
            fclose(_logfile); // ? check fclose success??
            if(sockfd != 0) close(sockfd);
            exit(errno);
        };
        iface_stat_data = HandlePacket(data_buff, iface_stat_data);
    };
    free(data_buff);
    return;
}

////////
//STOP//
////////
void Stop(){

    // merge statistics files
    FILE* f1;
    if((f1 = fopen("statistics.txt", "a")) == NULL){
        printf("%s%s\n", "Can't open file statistics.txt: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    FILE* f2;
    if((f2 = fopen("tmp_stat.txt", "a+")) == NULL){
        printf("%s%s\n", "Can't open file tmp_stat.txt: ", strerror(errno));
        exit(EXIT_FAILURE);
    };

    ssize_t read_f2 = 0;
    size_t  len_f2 = 0;
    char    *_line_f2 = NULL;
    while ((read_f2 = getline(&_line_f2, &len_f2, f2)) != -1) {
        fprintf(f1, "%s", _line_f2);
    };
    fclose(f1);
    FILE* f3 = freopen("tmp_stat.txt", "w", f2); //clear tmp_stat.txt
    fclose(f3);
    if(strcmp(_argv, "stop") == 0){
        if((_logfile = fopen("logfile.txt","a")) == NULL){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(_logfile, "%s\t%s\n", GetTime(), "stop");
        fclose(_logfile);
        FILE* f0;
        if((f0 = fopen("statistics.txt", "a")) == NULL){
            printf("%s%s\n", "Can't open file statistics.txt: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(f0, "%s %s\n", GetTime(), "stop\n");
        fclose(f0);
    };
    int cur_pid = (int) getpid();
    char command[15];
    strcpy(command, "kill ");
    ssize_t read_pipe = 0;
    char* _line_pipe = NULL;
    size_t len_p = 0;
    FILE* _pipe;
    if((_pipe = popen("pgrep pack", "r")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR, "%s%s", "popen() error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    while ((read_pipe = getline(&_line_pipe, &len_p, _pipe)) != -1) {
        if(_line_pipe == NULL){
            printf("%s\n", "Can't get PID.");
            exit(EXIT_FAILURE);
        }
        for (int i = 0; i < read_pipe; i++) {
            if (_line_pipe[i] == '\n') {
                _line_pipe[i] = '\0';
                break;
            };
        };
        int N = atoi(_line_pipe);
        if (N == cur_pid) {
            break;
        };
        strcat(command, _line_pipe);
        if ((system(command)) < 0) {
            syslog(LOG_ERR, "%s %s \n", "Can't kill packcatch process. ", strerror(errno));
            exit(EXIT_FAILURE);
        };
    };
    pclose(_pipe);
    syslog(LOG_NOTICE, "%s \n", "Daemon packcatch stopped.");
    return;
}


/////////////////
//SHOW IP COUNT//
/////////////////
void ShowIpCount(char *_ip_addr){

    FILE* stat_file;
    if((stat_file = fopen("statistics.txt", "r")) == NULL){
        syslog(LOG_ERR, "%s %s ", "Failed to open statistics.txt for show IP statistic. ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    ssize_t line_sz;
    size_t len;
    char *line = NULL;
    int ip_found = 0;
    while((line_sz = getline(&line, &len, stat_file)) != -1){
        if(strstr(line, _ip_addr) != NULL){
            int ip_len = strlen(_ip_addr);
            if(line[ip_len] == '\t'){
                printf("%s", line);
                ip_found = 1;
            };
        };
    };
    if(ip_found == 0){
        printf("%s\n", "Requested IP adress not found. ");
    };
    fclose(stat_file);
    return;
}

//////////////
//STAT IFACE//
//////////////
void StatIface(char *_stat_iface){
    FILE* _show_stat;
    if((_show_stat = fopen("statistics.txt", "r")) == NULL){
        syslog(LOG_ERR, "%s %s ", "Failed to open statistics.txt. ", strerror(errno));
        exit(EXIT_FAILURE);
    };

    if((strcmp(_stat_iface,"all") == 0)){
        ssize_t line_sz;
        size_t len;
        char *readline = NULL;
        while ((line_sz = getline(&readline, &len, _show_stat)) != -1) {
            printf("%s", readline);
        };
        return;
    };
    int iface_found = 0;
    for(int i = 0; i < iface_nmbr; i++){
        if(strcmp(_stat_iface, _iface_arr[i]) == 0){
            iface_to_stat = i;
            iface_found = 1;
            break;
        };
    };
    if(iface_found == 0){
        printf("%s\n", "Unknown interface. Type ''ls /sys/class/net'' in terminal to see available interfaces.");
        fclose(_show_stat);
        return;
    };
    printf("\n%s%s%s\n", "**********Statistics for interface ", _iface_arr[iface_to_stat], "**********");
    ssize_t line;
    size_t line_len;
    char *file_line = (char *)malloc(200);
    char *next_line = (char *)malloc(200);
    while((line = getline(&file_line, &line_len, _show_stat)) != -1){
        if(strstr(file_line, _iface_arr[iface_to_stat]) != NULL){
            printf("%s", file_line);
            while((line = getline(&next_line, &line_len, _show_stat) != -1) && next_line[0] != '-'){
                printf("%s", next_line);
            };
            printf("%s\n", " ");
        };
    };
    fclose(_show_stat);
    return;
}

///////////////////////////////////////////////////////////////////////////
////////////////////////////*********MAIN*********/////////////////////////
///////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]){

    if(argc < 2){
        printf("%s\n", "Enter arguments!\n");
        printf("\t\t%s", "Commands to use:\n");
        printf("%s", "| start |\t\t\tstart sniff default interface (ethernet 0);\n");
        printf("%s", "| stop |\t\t\tstop sniff any interface;\n");
        printf("%s", "| select iface [iface] |\tstart sniff from selected interface;\n\t\t\t\t\t\t\tto see available interfaces type 'ls /sys/class/net'\n");
        printf("%s", "| stat [iface] |\t\tprint to standard output gathered statistics for particular interface;\n\t\t\t\t\t\t\tif [iface] omitted - print statistics for all interfaces;\n");
        printf("%s", "| show [ip] count |\t\tprint to standard output for requested IP address quantity of packets and time\n");
        return 1;
    };
    //PROGRAM GET PARAMETERS! LET'S GO!//

    FILE* _pipe_dir;
    close(2);
    if((_pipe_dir = popen("sudo mkdir /opt/sniffer", "w")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR, "%s%s", "popen() error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
	pclose(_pipe_dir);
    const char *_work_dir = "/opt/sniffer";
    if(chdir(_work_dir) < 0){
        printf("%s%s", "Change working directory error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };

    /*              variant 1             */
    /*GET LIST OF COMPUTER NETWORK DEVICES*/
    FILE* _iface_pipe;
    if((_iface_pipe = popen("ls /sys/class/net", "r")) == NULL){
        syslog(LOG_DAEMON | LOG_ERR, "%s%s", "popen() error: ", strerror(errno));
        exit(EXIT_FAILURE);
    };
    ssize_t read_sz = 0;
    size_t len = 0;
    char *readline = NULL;
    for(int k = 0;(read_sz = getline(&readline, &len, _iface_pipe)) != -1; ++k){
        if(readline == NULL){
            syslog(LOG_ERR, "%s", "File interfaces.txt empty.");
            exit(EXIT_FAILURE);
        };
        readline[read_sz - 1] = '\0';
        _iface_arr[k] = readline;
        iface_nmbr++;
        readline = NULL;
    };
    pclose(_iface_pipe);


    /*              variant 2             */
    /*GET LIST OF COMPUTER NETWORK DEVICES*/
        /*
    if((_all_ifaces = fopen("interfaces.txt", "r")) == NULL){
        syslog(LOG_ERR, "%s %s", "Open interfaces.txt error:", strerror(errno));
        exit(EXIT_FAILURE);
    };

    ssize_t read_sz = 0;
    size_t len = 0;
    char *readline = NULL;
    for(int k = 0;(read_sz = getline(&readline, &len, _all_ifaces)) != -1; ++k){
        if(readline == NULL){
            syslog(LOG_ERR, "%s", "File interfaces.txt empty.");
            exit(EXIT_FAILURE);
        };
        readline[read_sz -1] = '\0';
        _iface_arr[k] = readline;
        iface_nmbr++;
        readline = NULL;
    };
    fclose(_all_ifaces);
    */



    /*SET DEFAULT INTERFACE (eth0)*/
    /*on my laptop - enp1s0*/
    char e = 'e';
    for(int i = 0; i < iface_nmbr; i++){
        char first_char = *_iface_arr[i];
        if(first_char == e){
            _default_iface = _iface_arr[i];
            snif_default = i;
            break;
        };
    };
    _curr_iface = _default_iface;
    iface_to_snif = snif_default;


                            /*********************************/
                            /**************START**************/
    if((strcmp(argv[1],"start")) == 0){
        printf("%s\n", "Start packet sniffer with default ethernet interface.");
        Start();
        printf("%s\n", "Done.");
        exit(EXIT_SUCCESS);
    }
    else
                            /********************************/
                            /**************STOP**************/
    if((strcmp(argv[1],"stop")) == 0){
        _argv = "stop";
        printf("%s", "Stop packet sniffer...");
        Stop();
        printf("%s\n", " Done.\nSee:\n\t/opt/sniffer/statistics.txt file with results;\n\t/opt/sniffer/logfile.txt with log info;\n");
        exit(EXIT_SUCCESS);
    }
    else
                        /**************SHOW [IP] COUNT**************/
    if((strcmp(argv[1],"show") == 0) && (strcmp(argv[3],"count") == 0)){
        _ip_addr = argv[2];
        /* LOG */
        if((_logfile = fopen("logfile.txt","a")) == NULL){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(_logfile, "%s\t%s %s %s\n", GetTime(), argv[1], argv[2], argv[3]);
        fclose(_logfile);

        printf("%s\n\n", "If daemon is running type 'pack_d stop' to stop the daemon and get full statistic.");
        ShowIpCount(_ip_addr);                              //*SHOW IP COUNT*//
        printf("\n%s\n", "If daemon is running type 'pack_d stop' to stop the daemon and get full statistic.");
        printf("%s\n", "Show information about IP done");
        exit(EXIT_SUCCESS);
    }
    else
                        /*************SELECT INTERFACE*************/ //CHECK
    if((strcmp(argv[1],"select") == 0) && (strcmp(argv[2],"iface") == 0)){

        _argv = "change_iface";
        if( argv[3] == NULL ){
            printf("%s\n", "Exit FAILURE. You must specify interface name. Type ''ls /sys/class/net'' to see the list");
            exit(EXIT_FAILURE);
        };
        int iface_found = 0;
        for(int i = 0; i < iface_nmbr; i++){
            if((strcmp( argv[3], _iface_arr[i] )) == 0){
                _curr_iface = _iface_arr[i];
                iface_to_snif = i;
                iface_found = 1;
                break;
            };
        };
        // if user try to select interface that is not in list of avaliable interfaces
        if(iface_found == 0){
            printf("\n %s \n", "Unknown interface. See the list of avaliable intefaces in /sys/class/net.");
            printf("%s \n", "Interface to snif set to default - ethernet0.");
            _curr_iface = _default_iface;
            iface_to_snif = snif_default;
        };
        /* LOG */
        if((_logfile = fopen("logfile.txt","a")) == NULL){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(_logfile, "%s\t%s %s %s\n", GetTime(), argv[1], argv[2], argv[3]);
        fclose(_logfile);
                        /*restart the daemon*/
        printf("%s%s%s\n", "Start sniff ", argv[3], " interface...");
        Stop();                 /*STOP*/
        Start();                /*START*/
        printf("%s\n", "Done.");
        exit(EXIT_SUCCESS);
    }
    else
                                /*********************************/
                                /***********STAT IFACE************/
    if(strcmp(argv[1],"stat") == 0){
        char *_iface = argv[2];
        if(_iface == NULL){
            _iface = "all";
        };
        printf("\n%s\n\n", "If daemon is running type 'pack_d stop' to stop the daemon and get full statistic.");
        if((_logfile = fopen("logfile.txt","a")) == NULL){
            syslog(LOG_DAEMON | LOG_ERR,"%s%s", "Open logfile.txt error: ", strerror(errno));
            exit(EXIT_FAILURE);
        };
        fprintf(_logfile, "%s\t%s %s\n", GetTime(), argv[1], _iface);
        fclose(_logfile);
        StatIface(_iface);
        printf("\n%s\n\n", "If daemon is running type 'pack_d stop' to stop the daemon and get full statistic.");
        exit(EXIT_SUCCESS);
    };
    exit(0);
}
