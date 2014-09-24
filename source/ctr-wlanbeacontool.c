#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>

#include "utils.h"

int main(int argc, char **argv)
{
	int ret;
	int argi;
	int linktype=0;
	pcap_t *pcap;
	struct pcap_pkthdr *pkt_header = NULL;
	const u_char *pkt_data = NULL;
	unsigned int framesize = 0, framestart = 0;
	unsigned char *framebuf = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	char inpath[256];
	unsigned char tmpbuf[0x20];

	if(argc<2)
	{
		printf("ctr-wlanbeacontool by yellows8\n");
		printf("Tool for parsing and generating 3DS local-WLAN beacons.\n");
		printf("Usage:\n");
		printf("ctr-wlanbeacontool <options>\n");
		printf("Options:\n");
		printf("--inpcap=<path> Input pcap to parse. This is used with pcap_open_offline(), therefore the 'path' can be '-' to use stdin for the pcap input.\n");

		return 0;
	}

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(inpath, 0, 256);

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--inpcap=", 9)==0)strncpy(inpath, &argv[argi][9], 255);
	}

	if(inpath[0]==0)return 0;

	pcap = pcap_open_offline(inpath, errbuf);
	if(pcap==NULL)
	{
		pcap_perror(pcap, "pcap_open_offline() failed: ");
		return 1;
	}

	linktype = pcap_datalink(pcap);

	while(1)
	{
		ret = pcap_next_ex(pcap, &pkt_header, &pkt_data);
		if(ret==0)continue;
		if(ret==-2)break;
		if(ret==-1)
		{
			pcap_perror(pcap, "pcap_next_ex() failed: ");
			pcap_close(pcap);
			return 1;
		}

		framesize = pkt_header->caplen;
		framestart = 0;

		if(linktype==DLT_IEEE802_11_RADIO)framestart+=0x20;

		memset(tmpbuf, 0, 0x20);
		tmpbuf[0] = 0x80;

		if(framestart)framesize-= framestart;

		if(memcmp(&pkt_data[framestart], tmpbuf, 4)==0)//Check for beacon frame.
		{
			tmpbuf[0] = 0;
			tmpbuf[1] = 8;
			if(memcmp(&pkt_data[framestart+0x24], tmpbuf, 0xa)==0)//Check for all-zero 8-byte SSID.
			{
				framebuf = (unsigned char*)malloc(framesize);
				if(framebuf==NULL)
				{
					printf("Failed to alloc mem for framebuf.\n");
					pcap_close(pcap);
					return 2;
				}

				memcpy(framebuf, &pkt_data[framestart], framesize);

				ret = 0;
				break;
			}
		}
	}

	pcap_close(pcap);

	if(ret==-2)
	{
		printf("End of pcap reached without finding the target beacon.\n");
		return 0;
	}

	if(ret==0 && framesize)
	{
		printf("Successfully located the beacon.\n");
		hexdump(framebuf, framesize);
	}

	if(framesize)free(framebuf);

	return 0;
}

