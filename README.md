# DNS Attack Simulator
For running the attack, all the attack have this same input (some optional) variables:
+ The direction and name of the .pcap file that is going to be modified (the input file) must be submitted by the parameter --input_file or it's shortcut -i.
  - For example -i /path/to/file/myFile.pcap

+ The direction of the output file and it's name which is going to be created with the attacks on it must be submitted by the argument --output_file or -o. The directory path have to exist.
  - Example -o /path/to/output/outFile.pcap

+ For submiting the duration of the attack, use the --duration and then the time (in seconds). The default value of this parameter is 60 seconds.

+ The number of computers on the botnet can be setted by the parameter --num_zombies or the shortcut -z. The value that is setted by default is 1, hence the type of the attack by default is a DOS.

+ The initial time of the attack, which is measured in order of the initial time of the first packet of the input file, can be submitted by the argument --initial_time (or -it). This is measure in seconds and it's default value is 0.

+ The number of packets to send during each second of the attack (the rate of packets per second) is setted by the argument --num_packet or -n. The default value it's determined by the attack to simulate.

+ On the other side, the size of the time window to establish the tolerance of the server is established by the argument --window_size, or either way -w it's the shortcut for this argument. This is measured in seconds and it's default is 0.01


+ On a same way, the number of query packets that the server can generate it's responses on the time window defined. This argument is being set by the command -p or --packets_per_window, and the default value is 100 packet per window.

  + For example if the window is 0.001 seconds, and the -p is 10, then it's interpretation is 10 packets per 0.001 seconds.


+  In the IP direction of the server that is going to be attacked on the simulation, now this can be set by the argument --server_ip or -s. The default value is the DNS server of blanco that it's IP is 200.7.4.7

+ The original port of the queries, that can be set by the argument -source_port and it's shortcut -sp. Some attack may not have it.
