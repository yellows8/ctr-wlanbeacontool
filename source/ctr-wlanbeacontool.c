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

unsigned int tagpos_ouitype14, tagpos_ouitype15, tagpos_ouitype18, tagpos_ouitype19;

char outpath_oui15[256];
char inpath_oui15[256];
char plaindataout_path[256];

//CRC polynomial 0xedb88320
unsigned int crc32_table[] = {
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

unsigned int calc_crc32(unsigned char *buf, unsigned int size, unsigned int initval, unsigned int outxor)
{
	unsigned int crc = initval;
	unsigned char val;

	while(size>0)
	{
		size--;
		val = *buf++;
		crc = crc32_table[(val ^ crc) & 0xff] ^ (crc >> 8);
	}

	return crc ^ outxor;
}

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

int parse_tag(unsigned char *tag, unsigned int tagsize, unsigned int tagpos)
{
	FILE *f;
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

		tagpos_ouitype14 = tagpos;
	}
	else if(ouitype==0x15)
	{
		if(tagsize<0x34)
		{
			printf("Tag size is too small.\n");
			return 1;
		}

		if(outpath_oui15[0])
		{
			f = fopen(outpath_oui15, "wb");
			if(f==NULL)
			{
				printf("Failed to open output file for OUI type 0x15 tag-data.\n");
			}
			else
			{
				fwrite(tag, 1, tagsize, f);
				fclose(f);
			}
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

		tagpos_ouitype15 = tagpos;
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

		tagpos_ouitype18 = tagpos;
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

		tagpos_ouitype19 = tagpos;
	}
	else
	{
		hexdump(tag, tagsize);
		printf("\n");
	}

	return 0;
}

int crypt_beacon(unsigned char *framebuf)
{
	int i;

	AES_KEY aeskey;
	unsigned int aes_num;
        unsigned char aes_ecount[AES_BLOCK_SIZE];
	unsigned char ctr[0x10];

	memset(ctr, 0, 0x10);

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
       	 	return 1;
    	}

	AES_ctr128_encrypt(cryptobuf, cryptobuf, cryptobuf_size, &aeskey, ctr, aes_ecount, &aes_num);

	return 0;
}

int parse_beacon(unsigned char *framebuf, unsigned int framesize)
{
	FILE *f;
	int ret=0;
	int i;
	unsigned int pos, tmpval;
	unsigned int crcval, crcvalframe;

	unsigned char hash[0x10];

	printf("Successfully located the beacon.\n");
	hexdump(framebuf, framesize);
	printf("\n");

	crcval = calc_crc32(framebuf, framesize-4, ~0, ~0);
	crcvalframe = getle32(&framebuf[framesize-4]);

	printf("FCS: ");
	if(crcval==crcvalframe)printf("Valid.\n");
	if(crcval!=crcvalframe)printf("Invalid(calc 0x%08x frame 0x%08x).\n", crcval, crcvalframe);

	printf("\n");
	printf("Host MAC address: ");
	for(i=0; i<6; i++)
	{
		printf("%02x", framebuf[0x0a+i]);
		if(i<5)printf(":");
	}
	printf("\n\n");

	memset(networkstruct, 0, sizeof(networkstruct));
	memset(hash, 0, 0x10);

	tagpos_ouitype14 = 0;
	tagpos_ouitype15 = 0;
	tagpos_ouitype18 = 0;
	tagpos_ouitype19 = 0;

	pos = 0x24;
	while(pos<framesize)
	{
		tmpval = framebuf[pos+1] + pos+2;
		if(tmpval>framesize)break;

		if(framebuf[pos]==0xdd)
		{
			ret = parse_tag(&framebuf[pos+2], framebuf[pos+1], pos);
			if(ret!=0)
			{
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

			ret = crypt_beacon(framebuf);
			if(ret!=0)return ret;

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

			if(plaindataout_path[0])
			{
				f = fopen(plaindataout_path, "wb");
				if(f==NULL)
				{
					printf("Failed to open output file for decrypted beacon data.\n");
				}
				else
				{
					fwrite(cryptobuf, 1, cryptobuf_size, f);
					fclose(f);
				}
			}
		}
	}

	return ret;
}

int generate_beacon(unsigned char *inframebuf, unsigned char *framebuf, unsigned int framestart, unsigned int framesize, struct pcap_pkthdr *pkthdr)
{
	FILE *f;
	int ret=0;
	unsigned int pos=0, size=0;
	unsigned int crcval;
	unsigned int tagsize;
	unsigned char *tagptr;
	unsigned char tagbuf[0x100];
	unsigned char hash[0x14];

	memcpy(framebuf, inframebuf, framestart);
	inframebuf+= framestart;
	framebuf+= framestart;

	if(tagpos_ouitype14==0)
	{
		printf("Tag for vendor OUI-type 0x14 doesn't exist in the input beacon, or is invalid.\n");
		return 8;
	}

	if(tagpos_ouitype15==0)
	{
		printf("Tag for vendor OUI-type 0x15 doesn't exist in the input beacon, or is invalid.\n");
		return 8;
	}

	if(tagpos_ouitype18==0)
	{
		printf("Tag for vendor OUI-type 0x18 doesn't exist in the input beacon, or is invalid.\n");
		return 8;
	}

	memcpy(framebuf, inframebuf, tagpos_ouitype14);
	
	pos = tagpos_ouitype14;
	size = inframebuf[tagpos_ouitype14+1]+2;
	memcpy(&framebuf[pos], &inframebuf[tagpos_ouitype14], size);
	pos+= size;

	tagsize = inframebuf[tagpos_ouitype15+1];
	tagptr = &inframebuf[tagpos_ouitype15+2];

	if(inpath_oui15[0])
	{
		f = fopen(inpath_oui15, "rb");
		if(f==NULL)
		{
			printf("Failed to open input file for OUI type 0x15 tag-data.\n");
		}
		else
		{
			memset(tagbuf, 0, 0x100);
			tagsize = fread(tagbuf, 1, 0x100, f);
			fclose(f);
			tagptr = tagbuf;
		}
	}

	memset(&tagptr[0x1F], 0, 0x14);
	SHA1(tagptr, 0x34 + tagptr[0x33], hash);
	memcpy(&tagptr[0x1F], hash, 0x14);

	size = tagsize;
	framebuf[pos] = 0xdd;
	framebuf[pos+1] = tagsize;
	pos+= 2;
	memcpy(&framebuf[pos], tagptr, size);
	pos+= size;

	memcpy(&networkstruct[0xc], tagptr, 0x1F);
	cryptobuf_size = 0x12 + 0x1E*networkstruct[0x1D];

	if(nwmbeacon_keyloaded && cryptobuf_size)
	{
		MD5(&cryptobuf[0x10], cryptobuf_size-0x10, hash);
		memcpy(cryptobuf, hash, 0x10);

		ret = crypt_beacon(framebuf);
		if(ret!=0)return ret;

		size = cryptobuf_size;
		if(size>0xFA)size = 0xFA;

		tagbuf[0] = 0x00;
		tagbuf[1] = 0x1f;
		tagbuf[2] = 0x32;
		tagbuf[3] = 0x18;

		framebuf[pos] = 0xdd;
		framebuf[pos+1] = size+4;
		pos+= 2;
		memcpy(&framebuf[pos], tagbuf, 4);
		pos+=4;
		memcpy(&framebuf[pos], cryptobuf, size);
		pos+= size;

		if(cryptobuf_size>0xFA)
		{
			size = cryptobuf_size - 0xFA;
			if(size>0xFA)size = 0xFA;

			tagbuf[3] = 0x19;

			framebuf[pos] = 0xdd;
			framebuf[pos+1] = size+4;
			pos+= 2;
			memcpy(&framebuf[pos], tagbuf, 4);
			pos+=4;
			memcpy(&framebuf[pos], &cryptobuf[0xFA], size);
			pos+= size;
		}
	}
	else
	{
		size = inframebuf[tagpos_ouitype18+1]+2;
		memcpy(&framebuf[pos], &inframebuf[tagpos_ouitype18], size);
		pos+= size;

		if(tagpos_ouitype19)
		{
			size = inframebuf[tagpos_ouitype19+1]+2;
			memcpy(&framebuf[pos], &inframebuf[tagpos_ouitype19], size);
			pos+= size;
		}
	}

	framesize = pos+4;

	crcval = calc_crc32(framebuf, framesize-4, ~0, ~0);
	putle32(&framebuf[framesize-4], crcval);

	framesize+= framestart;

	pkthdr->caplen = framesize;
	pkthdr->len = pkthdr->caplen;

	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int argi;
	int linktype=0;
	int snaplen;
	pcap_dumper_t *pcap_dumper;
	pcap_t *pcap;
	struct pcap_pkthdr *pkt_header = NULL;
	struct pcap_pkthdr pkthdr;
	const u_char *pkt_data = NULL;
	unsigned int framesize = 0, framestart = 0;
	unsigned char *inframebuf = NULL, *outframebuf = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	char inpath[256];
	char outpath[256];
	unsigned char tmpbuf[0x20];

	if(argc<2)
	{
		printf("ctr-wlanbeacontool by yellows8\n");
		printf("Tool for parsing and generating 3DS local-WLAN beacons.\n");
		printf("Usage:\n");
		printf("ctr-wlanbeacontool <options>\n");
		printf("Options:\n");
		printf("--inpcap=<path> Input pcap to parse. This is used with pcap_open_offline(), therefore the 'path' can be '-' to use stdin for the pcap input.\n");
		printf("--outpcap=<path> Output pcap to write. This is used with pcap_dump_open(), therefore the 'path' can be '-' to use stdout for the pcap output.\n");
		printf("--outoui15=<path> Output path to write the data from the OUI-type 0x15 tag data.\n");
		printf("--inoui15=<path> Input path to read the tag-data from for generating the OUI-type 0x15 tag.\n");
		printf("--outplain=<path> Output path for the decrypted beacon data.\n");

		return 0;
	}

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(inpath, 0, 256);
	memset(outpath, 0, 256);
	
	memset(outpath_oui15, 0, 256);
	memset(inpath_oui15, 0, 256);
	memset(plaindataout_path, 0, 256);

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--inpcap=", 9)==0)strncpy(inpath, &argv[argi][9], 255);
		if(strncmp(argv[argi], "--outpcap=", 10)==0)strncpy(outpath, &argv[argi][10], 255);
		if(strncmp(argv[argi], "--outoui15=", 11)==0)strncpy(outpath_oui15, &argv[argi][11], 255);
		if(strncmp(argv[argi], "--inoui15=", 10)==0)strncpy(inpath_oui15, &argv[argi][10], 255);
		if(strncmp(argv[argi], "--outplain=", 11)==0)strncpy(plaindataout_path, &argv[argi][11], 255);
	}

	if(inpath[0]==0)return 0;

	ret = load_key("nwmbeacon_key", 0x10, nwmbeacon_key);
	nwmbeacon_keyloaded = 0;
	if(ret==0)nwmbeacon_keyloaded = 1;

	if(nwmbeacon_keyloaded==0)
	{
		printf("Failed to load nwmbeacon_key, crypto will be disabled.\n");
	}

	cryptobuf = (unsigned char*)malloc(0x4000);
	cryptobuf_size = 0;
	cryptotags_bitmask = 0;

	if(cryptobuf==NULL)
	{
		printf("Failed to alloc mem for cryptobuf.\n");
		return 1;
	}

	memset(cryptobuf, 0, 0x4000);

	pcap = pcap_open_offline(inpath, errbuf);
	if(pcap==NULL)
	{
		pcap_perror(pcap, "pcap_open_offline() failed: ");
		free(cryptobuf);
		return 1;
	}

	linktype = pcap_datalink(pcap);
	snaplen = pcap_snapshot(pcap);

	while(1)
	{
		ret = pcap_next_ex(pcap, &pkt_header, &pkt_data);
		if(ret==0)continue;
		if(ret==-2)break;
		if(ret==-1)
		{
			pcap_perror(pcap, "pcap_next_ex() failed: ");
			pcap_close(pcap);
			free(cryptobuf);
			return 1;
		}

		framesize = pkt_header->caplen;
		framestart = 0;

		if(linktype==DLT_IEEE802_11_RADIO)framestart+= *((unsigned short*)&pkt_data[2]);

		if(framestart>framesize)continue;

		memset(tmpbuf, 0, 0x20);
		tmpbuf[0] = 0x80;

		if(framestart)framesize-= framestart;

		if(memcmp(&pkt_data[framestart], tmpbuf, 4)==0)//Check for beacon frame.
		{
			tmpbuf[0] = 0;
			tmpbuf[1] = 8;
			if(memcmp(&pkt_data[framestart+0x24], tmpbuf, 0xa)==0)//Check for all-zero 8-byte SSID.
			{
				inframebuf = (unsigned char*)malloc(0x4000);//This is the size used by 3ds code for NWMUDS:RecvBeaconBroadcastData.
				outframebuf = (unsigned char*)malloc(0x4000);
				if(inframebuf==NULL || outframebuf==NULL)
				{
					printf("Failed to alloc mem for inframebuf/outframebuf.\n");
					if(inframebuf)free(inframebuf);
					if(outframebuf)free(outframebuf);
					free(cryptobuf);
					pcap_close(pcap);
					return 2;
				}

				memcpy(&pkthdr, pkt_header, sizeof(struct pcap_pkthdr));

				memset(inframebuf, 0, 0x4000);
				memset(outframebuf, 0, 0x4000);
				memcpy(inframebuf, pkt_data, pkthdr.caplen);

				ret = 0;
				break;
			}
		}
	}

	if(inframebuf==NULL || outframebuf==NULL)framesize = 0;

	pcap_close(pcap);

	if(ret==-2)
	{
		printf("End of pcap reached without finding the target beacon.\n");
		free(inframebuf);
		free(outframebuf);
		free(cryptobuf);
		return 0;
	}

	if(framesize==0)return ret;

	if(ret==0)
	{
		ret = parse_beacon(&inframebuf[framestart], framesize);
	}

	if(outpath[0]==0 || ret!=0)
	{
		free(inframebuf);
		free(outframebuf);
		free(cryptobuf);
		return ret;
	}

	printf("Writing output pcap...\n");

	ret = generate_beacon(inframebuf, outframebuf, framestart, framesize, &pkthdr);

	free(inframebuf);
	free(cryptobuf);

	if(ret!=0)
	{
		printf("Beacon generation failed: %d\n", ret);
		free(outframebuf);
		return ret;
	}

	pcap = pcap_open_dead(linktype, snaplen);
	pcap_dumper = pcap_dump_open(pcap, outpath);
	if(pcap_dumper==NULL)
	{
		pcap_perror(pcap, "pcap_dump_open() failed: ");
		pcap_close(pcap);
		free(outframebuf);
		return 1;
	}

	pcap_dump((u_char*)pcap_dumper, &pkthdr, outframebuf);

	pcap_dump_close(pcap_dumper);

	free(outframebuf);

	return ret;
}

