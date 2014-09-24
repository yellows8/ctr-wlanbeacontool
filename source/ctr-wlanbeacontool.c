#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "utils.h"

unsigned int cryptobuf_size = 0;
unsigned char *cryptobuf = NULL;
unsigned int cryptotags_bitmask = 0;

int nwmbeacon_keyloaded = 0;
unsigned char nwmbeacon_key[0x10];

unsigned char networkstruct[0x108];

int load_key(char *filename, size_t size, unsigned char *keyout)
{
	FILE *f;
	size_t readsize = 0;
	char *home;
	char path[256];

	memset(path, 0, 256);
	home = getenv("HOME");
	if(home)snprintf(path, 255, "%s/.3ds/%s", home, filename);
	if(home==NULL)strncpy(path, filename, 255);

	f = fopen(path, "rb");
	if(f==NULL)return 1;
	readsize = fread(keyout, 1, size, f);
	fclose(f);

	if(readsize!=size)return 2;

	return 0;
}

int parse_tag(unsigned char *tag, unsigned int tagsize)
{
	int i;
	unsigned int ouitype=0;
	unsigned int tmpval;
	unsigned int additionaldatasize;
	unsigned char hash[0x14];
	unsigned char cmphash[0x14];

	ouitype = tag[3];

	memset(hash, 0, 0x14);
	memset(cmphash, 0, 0x14);

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

		cryptobuf_size = 0x12 + 0x1E*networkstruct[0x1D];
	}
	else if(ouitype==0x18)
	{
		cryptotags_bitmask |= 1;

		tmpval = cryptobuf_size;
		if(tmpval > 0xFA)tmpval = 0xFA;

		memcpy(cryptobuf, &tag[4], tmpval);

		printf("Tag data:\n");
		hexdump(&tag[4], tmpval);
		printf("\n");
	}
	else if(ouitype==0x19)
	{
		if(cryptobuf_size <= 0xFA)
		{
			printf("Extra OUI-type 0x19 tag detected which isn't needed: cryptobuf_size is only 0x%x bytes.\n", cryptobuf_size);
			return 0;
		}

		cryptotags_bitmask |= 2;
		tmpval = cryptobuf_size - 0xFA;

		memcpy(&cryptobuf[0xFA], &tag[4], tmpval);

		printf("Tag data:\n");
		hexdump(&tag[4], tmpval);
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
	int ret=0;
	int i;
	unsigned int pos, tmpval;

	AES_KEY aeskey;
	unsigned int aes_num;
        unsigned char aes_ecount[AES_BLOCK_SIZE];
	unsigned char ctr[0x10];
	unsigned char hash[0x10];

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

	cryptobuf = (unsigned char*)malloc(0x4000);
	cryptobuf_size = 0;
	cryptotags_bitmask = 0;

	if(cryptobuf==NULL)
	{
		printf("Failed to alloc mem for cryptobuf.\n");
		return 1;
	}

	memset(cryptobuf, 0, 0x4000);
	memset(networkstruct, 0, sizeof(networkstruct));
	memset(ctr, 0, 0x10);
	memset(hash, 0, 0x10);

	pos = 0x24;
	while(pos<framesize)
	{
		tmpval = framebuf[pos+1] + pos+2;
		if(tmpval>framesize)break;

		if(framebuf[pos]==0xdd)
		{
			ret = parse_tag(&framebuf[pos+2], framebuf[pos+1]);
			if(ret!=0)
			{
				free(cryptobuf);
				return ret;
			}
		}

		pos = tmpval;
	}

	if(nwmbeacon_keyloaded && cryptobuf_size)
	{
		if(!(cryptotags_bitmask & 1))
		{
			printf("Tag0(OUI-type 0x18) for encrypted data is missing.\n");
			ret = 4;
		}
		else if(!(cryptotags_bitmask & 2) && cryptobuf_size > 0xFA)
		{
			printf("Tag1(OUI-type 0x18) for encrypted data is missing.\n");
			ret = 4;
		}
		else
		{
			printf("Encrypted data:\n");
			hexdump(cryptobuf, cryptobuf_size);
			printf("\n");

			memcpy(ctr, &framebuf[0x0a], 6);
			putle32(&ctr[0x6], getbe32(&networkstruct[0x10]));
			ctr[0xa] = networkstruct[0x14];
			putle32(&ctr[0xc], getbe32(&networkstruct[0x18]));

			printf("CTR:\n");
			for(i=0; i<0x10; i++)printf("%02x", ctr[i]);
			printf("\n\n");

			aes_num = 0;
			memset(aes_ecount, 0, AES_BLOCK_SIZE);

			if (AES_set_encrypt_key(nwmbeacon_key, 128, &aeskey) < 0)
    			{
        			printf("Failed to set AES key.\n");
				free(cryptobuf);
       	 			return 1;
    			}

			AES_ctr128_encrypt(cryptobuf, cryptobuf, cryptobuf_size, &aeskey, ctr, aes_ecount, &aes_num);

			printf("Raw decrypted data:\n");
			hexdump(cryptobuf, cryptobuf_size);
			printf("\n");

			MD5(&cryptobuf[0x10], cryptobuf_size-0x10, hash);

			printf("Hash for the above data after decryption: ");
			for(i=0; i<0x10; i++)printf("%02x", hash[i]);
			if(memcmp(hash, cryptobuf, 0x10)==0)
			{
				printf(" (Valid)\n");
			}
			else
			{
				printf(" (Invalid)\n");
			}
			printf("\n");
		}
	}

	free(cryptobuf);

	return ret;
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

	ret = load_key("nwmbeacon_key", 0x10, nwmbeacon_key);
	nwmbeacon_keyloaded = 0;
	if(ret==0)nwmbeacon_keyloaded = 1;

	if(nwmbeacon_keyloaded==0)
	{
		printf("Failed to load nwmbeacon_key, crypto will be disabled.\n");
	}

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
		ret = parse_beacon(framebuf, framesize);
	}

	if(framesize)free(framebuf);

	return ret;
}

