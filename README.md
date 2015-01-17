#darbeli-matkap

DarbeliMatkap is a Network PCAP Fuzzer. It takes pcap file, fuzz it with different values and replays it to discover potential integer overflow and buffer overflow vulnerabilities.

DarbeliMatkap is written in Python by [SignalSEC](http://www.signalsec.com/) researchers.

Usage: ./darbelimatkap.py -n -i sample.pcap [-byteflip/-smash] [-d 0.2] [-ip 127.0.0.1] [-port 1234]

Arguments:  
            -n        : fuzzing mode
            -i        : sample pcap file
            -byteflip : byte flip fuzzing method
            -smash    : smash buffer fuzzing method
            -d        : delay time
            -ip       : target IP
            -port     : destination port
