#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#define u8	 unsigned char

#define CHECK_SIZE  	8
#define FLAG_SIZE  	32
#define ENC_FLAG_SIZE 	48
#define MAC_SIZE	6
#define KEY_SIZE	MAC_SIZE/2

char STR_BAD_MACHINE[]  = "I don't trust your machine.";
char STR_GOOD_MACHINE[] = "I trust your machine.\nHere is your flag:";

u8 ENC_FLAG[ENC_FLAG_SIZE] = 
{
	0xca,0x4a,0x34,0x68,0x5f,0xc1,0xbf,0xdc,0x11,0x38,0xf1,0x5f,0xa9,0x44,0x98,0x00,
	0x5e,0x16,0x20,0x19,0xb4,0xd5,0x85,0xe8,0x4a,0x87,0x94,0x1e,0x1a,0x29,0xf3,0x5c,
	0xec,0x87,0xf2,0x30,0xfc,0x8d,0xc7,0x62,0x15,0xaa,0xd9,0x92,0x7c,0x38,0xdf,0x72
};

void swap(u8 i, u8 j, u8 state[256])
{
	u8 tmp = state[i];
	state[i] = state[j];
	state[j] = tmp;
}

void rc3_setup(u8* key, int key_length, u8 state[256])
{
	int i;
	u8 j;
	
	for(i=0; i<256; i++)
	{
		state[i] = i;
	}

	for(j = i = 0; i < 256; i++) 
	{
		j += state[i] + key[i % key_length]; 
		swap( (u8)i, j, state);
	}
}

void rc3_crypt(u8* key, int key_length, u8* in, int size, u8* out)
{
	u8 state[256];
	int i=0;
	u8 j, index1=0, index2=0;

	rc3_setup(key, key_length, state);

	for(i=0; i<size; i++)
	{
		index1++;
		index2 ^= state[index1]; // this xor is an add in rc4
		swap(index1, index2, state);

		j = state[index1] + state[index2];

		out[i] = in[i] ^ state[j];
	}
}

int check_dec_buf(u8* buf)
{
	int i=0;
	u8 check = 0;

	for(i=0; i<CHECK_SIZE; i++)
	{
		check |= buf[i];
	}

	return check;
}

int decrypt_flag(u8 key[MAC_SIZE], char* flag)
{
	u8 tmp[ENC_FLAG_SIZE];
	int res;
	
	rc3_crypt(key, KEY_SIZE, ENC_FLAG, ENC_FLAG_SIZE, tmp);
	rc3_crypt(key+KEY_SIZE, KEY_SIZE, tmp, ENC_FLAG_SIZE, tmp);

	res = check_dec_buf(tmp);
	
	if( 0 == res )
	{
		memcpy(flag, tmp+CHECK_SIZE, ENC_FLAG_SIZE - CHECK_SIZE);
	}
	
	return res;	
}

int check_for_correct_mac_address(char* flag){
 	struct ifreq s;
  	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  
	strcpy(s.ifr_name, "eth0");
  	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) 
  	{
		return decrypt_flag( (u8*)s.ifr_addr.sa_data, flag );
  	}
  	else
  	{
   		return 1;
  	} 
}

int main(int argc, char* argv[])
{
	char flag[ENC_FLAG_SIZE - CHECK_SIZE + 1];
	memset(flag, 0, ENC_FLAG_SIZE - CHECK_SIZE + 1);

	if( 0 ==  check_for_correct_mac_address(flag) )
	{	
		printf("%s %s\n", STR_GOOD_MACHINE, flag);
	}
	else
	{
		printf("%s\n", STR_BAD_MACHINE);		
	}

	return 0;
}

