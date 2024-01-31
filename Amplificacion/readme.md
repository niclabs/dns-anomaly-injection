parser.add_argument('-p', '--packets_per_window', help='Server tolerance, packets per unit of time that the server can answer, default:100', type=int, default=100)
    
parser.add_argument('-w', '--window_size', help= 'Fraction of time for server tolerance, default: 0.01', type=float, default=0.01)
    
parser.add_argument('-s', '--server_ip', help = 'Server ip, default: 200.7.4.7', default='200.7.4.7')

    parser.add_argument('-sp', '--source_port', help = 'Source port, default:21517', type= int, default=21517)

    parser.add_argument('-d', '--duration', help = ' Duration of the attack (seconds), default: 300 sec.', type=int, default=300)

    parser.add_argument('-n', '--num_packets', help= 'Amount of packets per second per zombie, default: 1200', type=int, default=1200)

    parser.add_argument('-it', '--initial_time', help = 'Initial time of the attack, default:0', type=float, default=0)

    parser.add_argument('-rtype', '--response_type', help='Response type, true:amplified response, false:normal response. Default: false', action='store_true')

    parser.add_argument('-z', '--zombies', help='Number of computers in the botnet for the DDoS attack, default:1', type=int, default = 1)

requiredNamed = parser.add_argument_group('Required arguments')
    
    requiredNamed.add_argument('-i', '--input_file', help='Path to the input file.', required=True)
    
    requiredNamed.add_argument('-o','--output_file', help='Path to the output file.',required=True)
    
    requiredNamed.add_argument('-target', '--target_ip', help= 'Target ip', required=True)
    
    requiredNamed.add_argument('-dom','--domain', help= 'Asked domain, ex: "niclabs.cl"', required=True)

Set up attack