#include <iostream>
#include <string.h>
#include <math.h>
#include <vector>
#include <gmpxx.h>

#define mpz mpz_class
#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t
using namespace std;

static inline u32 rotl32 (u32 n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);  

  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

mpz sha1_hash(u8 message[], int msg_size){
	u64 pad_size = (u64) ceil((float) msg_size / 64.0) * 64;
	vector<u8> padded;
	
	u32 k = 0;
	u32 h0 = 0x67452301;
	u32 h1 = 0xefcdab89;
	u32 h2 = 0x98badcfe;
	u32 h3 = 0x10325476;
	u32 h4 = 0xc3d2e1f0;
	u32 a, b, c, d, e, f, temp;
	mpz hh;
	for(int i = 0; i < msg_size; i++){
		padded.push_back(message[i]);
	}
	padded.push_back(0x80);
	while((padded.size() + k + 8) % 64 != 0){
		k++;
	}
	for(unsigned int i = 0; i < k; i++){
		padded.push_back(0x0);
	}
	pad_size = msg_size * 8; //reuse pad_size for msg_len in bits
	padded.push_back((u8)(pad_size >> 0x38 & 0xff));
	padded.push_back((u8)(pad_size >> 0x30 & 0xff));
	padded.push_back((u8)(pad_size >> 0x28 & 0xff));
	padded.push_back((u8)(pad_size >> 0x20 & 0xff));
	padded.push_back((u8)(pad_size >> 0x18 & 0xff));
	padded.push_back((u8)(pad_size >> 0x10 & 0xff));
	padded.push_back((u8)(pad_size >> 0x8  & 0xff));
	padded.push_back((u8)(pad_size & 0xff));
	for(unsigned int i = 0; i < ceil(((float) padded.size()) / 64); i++){
		vector<u32> copy;
		for(unsigned int j = i * 64; j < (i + 1) * 64; j+=4){	
			copy.push_back(((((((padded[j] << 0x8) | padded[j+1]) << 0x8 ) | padded[j+2]) << 0x8) | padded[j+3])); 
		}
		for(unsigned int j = 16; j < 80; j++){
			copy.push_back(rotl32(copy[j-3] ^ copy[j-8] ^ copy[j-14] ^ copy[j-16], 1));
		}
		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		for(unsigned int j = 0; j < 80; j++){
			if(j >= 0 && j <= 19){
				f = (b & c) | ((~b) & d);
				k = 0x5a827999;	
			} else if(j >= 20 && j <= 39){
				f = b ^ c ^ d;
				k = 0x6ed9eba1;
			} else if(j >= 40 && j <= 59){
				f = (b & c) | (b & d) | (c & d);
				k = 0x8f1bbcdc;
			} else if(j >= 60 && j <= 79){
				f = b ^ c ^ d;
				k = 0xca62c1d6;
			}

			temp = rotl32(a, 5) + f + e + k + copy[j];
			e = d;
			d = c;
			c = rotl32(b, 30);
			b = a;
			a = temp;
		}

		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		copy.clear();
	}

	hh = ((mpz)h0 << 128) | ((mpz)h1 << 96) | ((mpz)h2 << 64) | ((mpz)h3 << 32) | (mpz)h4;
	return hh;
}

//'abc' = a9993e364706816aba3e2571000f0a18ddd0d89d
int main(int argc, char** argv){
	cout << "SHA-1 Test cases: " << endl;
	string str = "abc";
	u8 lol[str.size()];	
	for(unsigned int i = 0; i < str.size(); i++){
		lol[i] = (u8)str[i];
	}

	cout << "abc" << ": ";
	gmp_printf("%Zx\n\n", sha1_hash(lol, str.size()));

	str = "";
	lol[str.size()];
	for(unsigned int i = 0; i < str.size(); i++){
		lol[i] = (u8)str[i];
	}

	cout << "\"\" " << ": ";
	gmp_printf("%Zx\n\n", sha1_hash(lol, str.size()));

	str = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	lol[str.size()];
	for(unsigned int i = 0; i < str.size(); i++){
		lol[i] = (u8)str[i];
	}

	cout << str << ": ";
	gmp_printf("%Zx\n\n", sha1_hash(lol, str.size()));


	str = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	lol[str.size()];
	for(unsigned int i = 0; i < str.size(); i++){
		lol[i] = (u8)str[i];
	}

	cout << str << ": ";
	gmp_printf("%Zx\n\n", sha1_hash(lol, str.size()));

	str = "";
	for(int i = 0; i < 1000000; i++){
		str += 'a';
	}
	u8 temp[str.size()];
	for(unsigned int i = 0; i < str.size(); i++){
		temp[i] = (u8)str[i];
	}

	cout << "one million (1,000,000) repetitions of \"a\"" << ": ";
	gmp_printf("%Zx\n\n", sha1_hash(temp, str.size()));


	cout << "Test vectors taken from: https://di-mgt.com.au/sha_testvectors.html" << endl;

}
