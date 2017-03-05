Instructions HOWTO in the begining of the file pack.c  


Network incoming traffic packet sniffer. 

Directory to store the results of program work is /opt/sniffer. (may be changed. Edit the code.)
All options could be seen by calling program without parameters.
Reads available to network connection interfaces.
Chose first ethernet interface as default to sniff.
Gets daemonized with double fork()'ing.
Incoming traffic data stores in structure which is repeatedly rewrites to file "tmp_stat.txt" with every new incoming packet.
By the "stop" command program appends file "statistics.txt" with file "tmp_stat.txt" and clears the last one.
Changing interface operation automatically call "stop", so no data is missing.
