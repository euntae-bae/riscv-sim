//#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */
/*
 * Constants defined by the MD5 algorithm
 */
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476
typedef struct{
	uint64_t size;		  // Size of input in bytes
	uint32_t buffer[4];   // Current accumulation of hash
	uint8_t input[64];	  // Input to be used in the next step
	uint8_t digest[16];   // Result of algorithm
}MD5Context;
void md5Step(uint32_t *buffer, uint32_t *input);
uint32_t rotateLeft(uint32_t x, uint32_t n);
uint32_t F(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t G(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t H(uint32_t X, uint32_t Y, uint32_t Z);
uint32_t I(uint32_t X, uint32_t Y, uint32_t Z);
static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
					   5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,	9, 14, 20,
					   4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
					   6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
static uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
					   0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
					   0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
					   0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
					   0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
					   0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
					   0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
					   0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
					   0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
					   0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
					   0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
					   0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
					   0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
					   0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
					   0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
					   0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
/*
 * Bit-manipulation functions defined by the MD5 algorithm
 */
#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))
/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/*
 * Initialize a context
 */
void md5Init(MD5Context *ctx){
	ctx->size = (uint64_t)0;
	ctx->buffer[0] = (uint32_t)A;
	ctx->buffer[1] = (uint32_t)B;
	ctx->buffer[2] = (uint32_t)C;
	ctx->buffer[3] = (uint32_t)D;
}
/*
 * Add some amount of input to the context
 *
 * If the input fills out a block of 512 bits, apply the algorithm (md5Step)
 * and save the result in the buffer. Also updates the overall size.
 */
void md5Update(MD5Context *ctx, uint8_t *input_buffer, size_t input_len){
	uint32_t input[16];
	unsigned int offset = ctx->size % 64;
	ctx->size += (uint64_t)input_len;
	// Copy each byte in input_buffer into the next space in our context input
	for(unsigned int i = 0; i < input_len; ++i){
		ctx->input[offset++] = (uint8_t)*(input_buffer + i);
		// If we've filled our context input, copy it into our local array input
		// then reset the offset to 0 and fill in a new buffer.
		// Every time we fill out a chunk, we run it through the algorithm
		// to enable some back and forth between cpu and i/o
		if(offset % 64 == 0){
			for(unsigned int j = 0; j < 16; ++j){
				// Convert to little-endian
				// The local variable `input` our 512-bit chunk separated into 32-bit words
				// we can use in calculations
				input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
						   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
						   (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
						   (uint32_t)(ctx->input[(j * 4)]);
			}
			md5Step(ctx->buffer, input);
			offset = 0;
		}
	}
}
/*
 * Pad the current input to get to 448 bytes, append the size in bits to the very end,
 * and save the result of the final iteration into digest.
 */
void md5Finalize(MD5Context *ctx){
	uint32_t input[16];
	unsigned int offset = ctx->size % 64;
	unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;
	// Fill in the padding andndo the changes to size that resulted from the update
	md5Update(ctx, PADDING, padding_length);
	ctx->size -= (uint64_t)padding_length;
	// Do a final update (internal to this function)
	// Last two 32-bit words are the two halves of the size (converted from bytes to bits)
	for(unsigned int j = 0; j < 14; ++j){
		input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
				   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
				   (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
				   (uint32_t)(ctx->input[(j * 4)]);
	}
	input[14] = (uint32_t)(ctx->size * 8);
	input[15] = (uint32_t)((ctx->size * 8) >> 32);
	md5Step(ctx->buffer, input);
	// Move the result into digest (convert from little-endian)
	for(unsigned int i = 0; i < 4; ++i){
		ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
		ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
		ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
		ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
	}
}
/*
 * Step on 512 bits of input with the main MD5 algorithm.
 */
void md5Step(uint32_t *buffer, uint32_t *input){
	uint32_t AA = buffer[0];
	uint32_t BB = buffer[1];
	uint32_t CC = buffer[2];
	uint32_t DD = buffer[3];
	uint32_t E;
	unsigned int j;
	// main loop
	for(unsigned int i = 0; i < 64; ++i){
		switch(i / 16){
			case 0: // round 1
				E = F(BB, CC, DD);
				j = i;
				break;
			case 1:	// round 2
				E = G(BB, CC, DD);
				j = ((i * 5) + 1) % 16;
				break;
			case 2:	// round 3
				E = H(BB, CC, DD);
				j = ((i * 3) + 5) % 16;
				break;
			default: // round 4
				E = I(BB, CC, DD);
				j = (i * 7) % 16;
				break;
		}
		uint32_t temp = DD;
		DD = CC;
		CC = BB;
		BB = BB + rotateLeft(AA + E + K[i] + input[j], S[i]);
		AA = temp;
	}
	buffer[0] += AA;
	buffer[1] += BB;
	buffer[2] += CC;
	buffer[3] += DD;
}
/*
 * Functions that will return a pointer to the hash of the provided input
 */
uint8_t* md5String(const char *input, uint8_t *result){
	MD5Context ctx;
	md5Init(&ctx);
	md5Update(&ctx, (uint8_t *)input, strlen(input));
	md5Finalize(&ctx);
	memcpy(result, ctx.digest, 16);
	return result;
}
/*
 * Rotates a 32-bit word left by n bits
 */
uint32_t rotateLeft(uint32_t x, uint32_t n){
	return (x << n) | (x >> (32 - n));
}
// void print_bytes(void *p, size_t length){
//	   uint8_t *pp = (uint8_t *)p;
//	   for(unsigned int i = 0; i < length; ++i){
//		   if(i && !(i % 16)){
//			   printf("\n");
//		   }
//		   printf("%02X ", pp[i]);
//	   }
//	   printf("\n");
// }
// void print_hash(uint8_t *p){
//	   for(unsigned int i = 0; i < 16; ++i){
//		   printf("%02x", p[i]);
//	   }
//	   printf("\n");
// }

//#define KEY_NUM 500
#define KEY_NUM 10
//const char key[KEY_NUM][8] = { "HWJTRHKM", "JNCTCTLW", "MSEQLIPV", "OCOTTHRS", "GSFPBQTK", "VVVXIBOU", "LSFWTUUJ", "OCEBJVUP", "IRWJBRMP", "GJOPCUDO", "HAMCUADL", "CHMMUATE", "KSGLDKCK", "LJROVMEU", "NIOBJREL", "QJPNJLJL", "VHPQRJSF", "KLLIQPUF", "PLGAELEV", "MLCNODBL", "LQUUBOBE", "CEMKLIPD", "LNDQQXFE", "LXSBCTFN", "DBCUPDAJ", "IETTFCOQ", "QKAAJVFM", "UPGXCLEF", "EGRLCKVC", "GINDDEUL", "OMLPKIEW", "XKVBNSWR", "AIESSRUQ", "SCUVGIAM", "ULDWUXVL", "JKNOEDHF", "LEPVNMOH", "OCUMKUAG", "ATVMTSXU", "EEDJICGL", "GVBMBHLH", "JITTULRM", "XOAKAQWF", "UBGUEMIC", "BJOTQCCR", "COMORVDQ", "MTCELRJI", "SHEWLEBN", "FHINBCGD", "QKKCINSM", "ANQMGSMA", "BIPNNISS", "HSIJUGMF", "RWHBDRFE", "GVIEHUVJ", "EMOJMIUT", "CUEOCJTT", "XCMDURXS", "HXXOTUPP", "AFBMFNXH", "JEWLFJXE", "MLXAVWSU", "VJCIFSAV", "PRJVGJUP", "FSSKEROI", "VOIKESGS", "EISBSKXK", "DAXBBTIW", "GTICMPCB", "VCLRUJDQ", "KWKEIJGE", "BFVTRGRP", "BCRFJTHG", "VKPJMTCW", "RMSRNBVG", "WTBHRTWK", "NHPWSOUH", "RDRFWLTH", "PNRUGOCF", "BEEKPDUE", "CESVSGED", "JNIAADXH", "JQDPXWUQ", "SRDJUPFO", "TPLGNQJO", "VKOWFOVO", "WBGVXSOJ", "LRSXIPOU", "GRCLBDBX", "NIVTOSBM", "LXKCSALV", "JVNJMTFK", "MXVODXNI", "HCTVMVBA", "ULSGDGUE", "TJOIELSQ", "DIWWXLGG", "NCTSPUSD", "AEKDCGIW", "HOGDRQTU", "QSSPVRVD", "TIVKFHNF", "LPAONAMM", "GKPASLML", "VXCSQQND", "AKFVRKSF", "STLHTXUC", "BDSTOWGD", "VJOFBDIR", "OFPXQJEK", "EPJQGVKH", "BUDHSBDQ", "KRNDMOVS", "TESDNWFK", "GPSEEEMV", "AHFSIACL", "RQGVGTQR", "XKVFACPW", "JJDGFHDV", "OAPOAKRJ", "SAHQTXJL", "JWQBRHAC", "IDAFKECQ", "URWVTQGN", "IFFTEHGF", "FWHWVXRV", "CRCENEMK", "OCXJSFPS", "DMOHTUFR", "LEPIDIWF", "SABHFNRL", "HIUCGDMJ", "QCIDPNUC", "RECUEARW", "RSGOXPBH", "ANBGRFHB", "IPEPFRRO", "VLLBEUQV", "HWDWFEVV", "ROTKUCDE", "KITPREVO", "HAHLVXAE", "NDSLXQIR", "GUTCOXWA", "XRHQNFWV", "FVASVROC", "MJNMBOVX", "KQCQHARG", "KQOXNEUT", "CNFPGURS", "FHGWVDVX", "MPPTQASS", "RARWFGRX", "TPORLXLI", "GKWTFTSJ", "DCVLCPFL", "PWKMUTDH", "KRANREVP", "OTLLHVNC", "XKNSBSFI", "IHNFTQMF", "CNLLJACP", "MFCTDPNC", "BCUSUSTU", "BIBUAGSS", "LFFUVILJ", "FFUINJLO", "LXBXRUUL", "ENXUTJPW", "GMSEUVNS", "DKCQTFWX", "FPWOLKRH", "ARELCLKJ", "XUNMKCGN", "EIVAGLXL", "DNROQLWQ", "ESTWFVHU", "KMIUHOBL", "PWLVJCAM", "IRDAURIQ", "LDPIROED", "TFPCTQNC", "ORPPLHUT", "RPTNIDGL", "XNTIDPDW", "USQIKGCQ", "PSXCBTWS", "KJAKNGVE", "TIMOAPFU", "JVULTXTK", "RKFKGDVI", "MVTRTQVG", "RJURQRFR", "HSECRPFC", "CKMANBAR", "WTDJEAPV", "CEGKVDEE", "VIXOQEIK", "GNCLOCEF", "WHOSAGHS", "KNEXIIEG", "JTMRPVDV", "KFIQXEVN", "MMHESOOE", "TSDUTXSU", "KGNBTQWV", "NGOELLSP", "XBLJIBFT", "LBHGABCD", "AHETPTJE", "RXJUCTLS", "MODUHJIT", "KPRCJMVJ", "TCULNFHG", "UIDXDGJQ", "NEEUNEPP", "UJKFNXGI", "RCLGITNE", "TITXOEHD", "JLQOQHWE", "IABVXHWR", "JJPJUEGQ", "EBHLWOGX", "RWFBGDVG", "TWULVKUX", "LLIIIOQM", "IXXGFGFO", "EKQCGNBR", "EVEBXAQK", "MBKMHCAP", "RANOWSFC", "VVVTCWMG", "LJAKBQUN", "JHRJBSAT", "KOJIAGCN", "DXIWNNEA", "WUCXFXFG", "WWPPIQCS", "WECWKFEG", "UMEKRAKH", "VNHSEEAS", "SIJDQEVO", "IQESVAAR", "NEDWFGGS", "LFEPJUBT", "ECWUGMCO", "EXJBXBKE", "GGDDMBNX", "GRGPNXKK", "BBWINRWR", "IXKXBUEX", "SXCGQPVW", "ATFNSHPU", "IOUNHSGP", "SIOLFKKP", "BMWRTLPT", "XMARUQFE", "WBSFMQMW", "BCJWFTNW", "XDQSPXFG", "MFXINVEL", "OWICHUAI", "PJWMUDKT", "HCNOSKUG", "ILGVAKBP", "BBJIWKIF", "LGRAJTTI", "WBWILKOT", "OUJOGCFH", "DPHBRPWU", "NHUPDIXR", "JOBMQPIG", "DJVBLSJO", "BIISAGHN", "GDEJDUCM", "CDBSKBBN", "COONIPTK", "ADUQCDFA", "XCJCODHQ", "GACIRDVT", "RDISLTUL", "PQDJMAJL", "SSFAVEQT", "ETDVOQIA", "LIKWEGBT", "WUEKVNNH", "XLIMPQHM", "DCBSSKKF", "KUUOCVBQ", "SVTHCIGB", "LONTXMXC", "OAMACWGN", "KSTMPVVB", "KQANQHGE", "NMXMAWHH", "OTHRKFWM", "XJRHGOIJ", "GJWWIUCV", "IRCBHJIW", "UHHWNVLE", "GELFSUOA", "VEOFARSJ", "CUCKVCAS", "JHIOUTTC", "PGHJSNBH", "RQESBXTT", "TNFRPVDQ", "ULHQHSLO", "QSADARKR", "BPDSOOOB", "TLKKJNTV", "RCOQMBGE", "LGXLQKVJ", "RQEXXKAS", "VDFWQQUJ", "SCBWDISG", "GSKOEHAN", "PUMOGEJT", "HGKQWWRI", "ALWTTQRR", "KDAGCATS", "UXISEJND", "HXTVNNVN", "QTADMSUW", "NMFQMQKA", "QKKMMAPT", "PDRFIGKA", "CDDONPEC", "EJSISUBK", "HLWTDFGL", "APIIWKIA", "NDGSTKVP", "UHXOEQQD", "EGWXDUKE", "MSMCFNCK", "IIFDSSKG", "BCMFSUAO", "CWOWLACP", "LORITLSE", "TXXFJKEL", "MIIGVJVP", "XDNKDPBG", "WKORVJVI", "ANOKXKNL", "KVJHGWXW", "BMAVECDS", "MSLCTBKL", "OQNNCCQN", "QRMOQLMR", "QNGUHKOL", "URNHSAKA", "QAFLSVQK", "HEBXQNIA", "SPMBRSNF", "LSEWSOWD", "OUOJJGLQ", "KMPSSASM", "HGGQALVE", "FRCAHQDO", "MRPWPCOB", "PWMBOGNV", "FLNVWCBE", "TDUSMPIA", "IXOPSFQJ", "DUCRTHGA", "TLVRFXNQ", "SJKGATXA", "KNPESAFN", "UHWHHUHC", "XVTEMBUG", "KXFLKELU", "JTRUTOJH", "OAPVUOXM", "LKQPLFOW", "ETBOPECA", "PLUCCWKQ", "WRNKXEOD", "OHSSEIIA", "TJOCFIDV", "UPXWNBGD", "KTGKXUNF", "THPXIXXT", "AFWWOBTC", "QKQWMWRW", "RXIIMNFH", "NVXVMOQF", "UODCHWUQ", "IMGMKXLD", "PLDDBACG", "NBDCQLHE", "SKGRACJI", "OHNQHATO", "DORUOLCE", "NVWVBVBT", "HXMHROHH", "VUXUMKKI", "QTUWHXSM", "MQJNNCIM", "BNLSTLRI", "XIFEKHMS", "TIQSXLWM", "THBBBCNC", "PRMKEVKD", "FPXHPLBC", "MJMDUKPI", "RJJSLOMS", "HQUDNGXK", "OWRFKKXO", "TLRIVBQG", "KBQVPUPP", "MLSBRRDX", "QMUSWTIJ", "WRRTSBRE", "CJRKFABJ", "DLCVFFMN", "JJHHEHJD", "ASOLUIPW", "JBAPBBQF", "NTSKQGXC", "PWBMFKPV", "FVIBFQPP", "RQWSJOPO", "BJQSIPUX", "NVLKISIF", "QQWNINER", "VSEHBTNC", "VGUFNQET", "GIFGSNLK", "WJQWOMQM", "HULIHQCE", "WPJEXGXF", "GELAKODI", "XTWGHOKG", "CNGCFJGU", "AIAPGXVE", "DIUFPXNG", "KMMKSWQN", "LPPJANFQ", "NVHLUUPP", "VEVMTCSG", "GXIRVAGB", "PNCHSHPA", "UPDQDLXA", "PMEKPXIN", "WQGLJEEQ", "RGQEFHUB", "OXJKKJKB", "VPMEGMSU", "FAXOFEGO", "CWKIWGBE", "GLOIMRKB", "AOGGCQSX", "QRNNNUUQ", "KGAIFRFD", "ETLQMNSM", "DQKWIEVQ", "OLGDXSTB", "QLCVFHAB", "SEKHRULN", "MOLMSIEA", "LCECUPUN", "TWCAVTRP", "XDOQXSFD", "IIPSJMTU", "OXPDGLIB", "BCRWVLNU", "GUFGOCBW", "DJQMVLAD", "CHWJSGCT", "BUJWHXLN", "TILJCNXF", "WPRLDKOV", "RFGEDJPE", "VBDEQGJD", "ONEQSDWI", "SHTNRBLL", "GJPCKGGH", "XJLPPNSV", "SWOMBEUM", "LHBVAEIX", "OPBANHIN", "JLEQQPOK", "NUWHAKTL", "JMICRIBH", "PSXFRHKC", "LGLDVBOD", "NECNHVQI", "BRKSBDRJ", "NJGHQQBT", "OMXEFFXS", "BBXIOQJP", "JLCCPLDU", "UJDFRFAA", "JPEPUDBW", "EBWSJHBS", "TDMCHQWD", "RCADXBDI", "IHPFCRDG", "KBQTJRFU", "NJWURUPL"};
const char keys[][8] = { "HWJTRHKM", "JNCTCTLW", "MSEQLIPV", "OCOTTHRS", "GSFPBQTK", "VVVXIBOU", "LSFWTUUJ", "OCEBJVUP", "IRWJBRMP", "GJOPCUDO" };
uint8_t result[16];

uint64_t res = 0;
uint64_t key = 0x48574a5452484b4d; // "HWJTRHKM"
uint64_t num;
uint64_t *ptr;

int main(void) {
	// test0 rd, rs1, rs2
	//asm volatile("test0 x2, x0, x1");
	//asm volatile("li, t0, ");
	//asm volatile("")
	//asm volatile("ld %0, %1": "=r"(num) : "r"(key));
	//ptr = &key;
	//asm volatile("ld t0, ")
	//asm volatile("test0 t0, %0, x31" : "=r" (res) : "r" (key)); // rs2 is not uesd
	asm volatile("md5 t0, %0, x31" : "=r" (res) : "r" (key)); // rs2 is not uesd
	return 0;
}
