#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    u_char bssid_list[100][7] = {0, };
    u_int bssid_count[100] = {0, };
    int n = 0;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
        const u_char *bssid;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
        unsigned int rl = *(packet+2) + *(packet+3)*0xff;
        unsigned int ssid_len = *(packet+rl+37);
        printf("\nSSID : ");
        for(int i=0; i<ssid_len; ++i)
            printf("%c", *(packet+rl+38+i));
        printf("\nBSSID : ");
        bssid = packet+40;
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        unsigned int* numbeacon = packet+24;
        if(*numbeacon == 128) {
            if(n==0)
            {
                for(int i=0; i<6; ++i)
                {
                    bssid_list[0][i] = bssid[i];
                }
                bssid_list[0][6] = '\0';
                bssid_count[0]++;
                n++;
            }
            else
            {
                int flag;
                for(int i=0; i<n; ++i)
                {
                    flag = 1;
                    for(int j=0; j<6; ++j)
                    {
                        if(bssid_list[i][j] != bssid[j])
                        {
                            flag = 0;
                            break;
                        }
                    }
                    if(flag == 1)
                    {
                        bssid_count[i]++;
                        printf("BEACON : %u\n", bssid_count[i]);
                        break;
                    }
                }
                if(flag == 0)
                {
                    n++;
                    for(int i=0; i<6; ++i)
                    {
                        bssid_list[n-1][i] = bssid[i];
                    }
                    bssid_list[n-1][6] = '\0';
                    bssid_count[n-1]++;
                    printf("BEACON : %u\n", bssid_count[n-1]);
                }
            }
        }
	}

	pcap_close(pcap);
}
