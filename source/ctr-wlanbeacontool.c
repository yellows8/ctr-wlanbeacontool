#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <openssl/sha.h>

#include "utils.h"

int parse_tag(unsigned char *tag, unsigned int tagsize)
{
	int i;
	unsigned int ouitype=0;
	unsigned int additionaldatasize;
	unsigned char hash[0x14];
	unsigned char cmphash[0x14];
	unsigned char networkstruct[0x108];

	ouitype = tag[3];

	memset(hash, 0, 0x14);
	memset(cmphash, 0, 0x14);
	memset(networkstruct, 0, sizeof(networkstruct));

	printf("OUI(%02x%02x%02x) type 0x%02x:\n", tag[0], tag[1], tag[2], ouitype);

	if(ouitype==0x14)
	{
		printf("Data after OUI type:\n");
		hexdump(&tag[4], tagsize-4);
		printf("\n");
	}
	else if(ouitype==0x15)
	{
		if(tagsize<0x34)
		{
			printf("Tag size is too small.\n");
			return 1;
		}

		memcpy(&networkstruct[0xc], tag, 0x1F);
		additionaldatasize = tag[0x33];
		networkstruct[0x3F] = additionaldatasize;

		printf("Network struct:\n");
		hexdump(networkstruct, 0x108);
		printf("\n");

		memcpy(cmphash, &tag[0x1F], 0x14);
		memset(&tag[0x1F], 0, 0x14);
		SHA1(tag, 0x34 + additionaldatasize, hash);
		memcpy(&tag[0x1F], cmphash, 0x14);

		printf("Tag data hash: ");
		for(i=0; i<0x14; i++)printf("%02x", cmphash[i]);
		if(memcmp(hash, cmphash, 0x14)==0)
		{
			printf(" (Valid)\n");
		}
		else
		{
			printf(" (Invalid)\n");
		}

		printf("Additional data size: 0x%x.\n", additionaldatasize);
		if(additionaldatasize)
		{
			printf("Data:\n");
			hexdump(&tag[0x34], additionaldatasize);
			printf("\n");
		}

		printf("\n");
	}
	else
	{
		hexdump(tag, tagsize);
		printf("\n");
	}

	return 0;
}

int parse_beacon(unsigned char *framebuf, unsigned int framesize)
{
	int i;
	unsigned int pos, tmpval;

	printf("Successfully located the beacon.\n");
	hexdump(framebuf, framesize);

	printf("\n");
	printf("Host MAC address: ");
	for(i=0; i<6; i++)
	{
		printf("%02x", framebuf[0x0a+i]);
		if(i<5)printf(":");
	}
	printf("\n\n");

	pos = 0x24;
	while(pos<framesize)
	{
		tmpval = framebuf[pos+1] + pos+2;
		if(tmpval>framesize)break;

		if(framebuf[pos]==0xdd)
		{
			parse_tag(&framebuf[pos+2], framebuf[pos+1]);
		}

		pos = tmpval;
	}

	return 0;
}

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
				framebuf = (unsigned char*)malloc(0x4000);//This is the size used by 3ds code for NWMUDS:RecvBeaconBroadcastData.
				if(framebuf==NULL)
				{
					printf("Failed to alloc mem for framebuf.\n");
					pcap_close(pcap);
					return 2;
				}

				memset(framebuf, 0, 0x4000);
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
		parse_beacon(framebuf, framesize);
	}

	if(framesize)free(framebuf);

	return 0;
}

