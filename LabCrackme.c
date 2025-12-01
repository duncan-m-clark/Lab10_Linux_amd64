// SimpleCrackMe.cpp : Defines the entry point for the console application.
//

#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
typedef int BOOL;
#define FALSE 0
#define TRUE 1
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

#include <time.h>

#include <string.h>
#include <stdio.h>

#define DEBUGLINE fprintf(stderr, "DBG: %d\n", __LINE__)

#define S1(N) #N
#define S2(N) S1(N)
#define LINESTR S2(__LINE__)
#define SALT asm volatile("\
				 .intel_syntax noprefix\n\
				 mov rax, 2\n\
				 cmp rax, 2\n\
				 je .skip_junk" LINESTR "\n\
				 .byte 0x0f\n\
				 .skip_junk" LINESTR ":\n\
				 .att_syntax prefix\n\
				");

BOOL doCheck(char user[], unsigned char* key);

BOOL doCheckConvert(char user[], char keychars[]) {

	SALT
	pid_t parent_id = getppid();
	pid_t pid = fork();

	if(pid == 0){
		struct timespec start;

		clock_gettime(CLOCK_REALTIME, &start);
		long start_time = start.tv_sec * 1000000000 + start.tv_nsec;

		SALT
		while(1) {
			//printf("%d\n", getppid());
			struct timespec now;

			clock_gettime(CLOCK_REALTIME, &now);
			long current_time = now.tv_sec * 1000000000 + now.tv_nsec;
		if(getppid() == 1 || getppid() == 5468){
			printf("parent closed. Closing child");
			_exit(0);
		}
		if(current_time - start_time > 200000000) {
			printf("Debugger detected or program has ended. Closing\n");
			printf("%d\n", getppid());
			kill(parent_id, SIGKILL); 
			_exit(0);
		}
		usleep(50000);
		}
		
		_exit(0);
	}
		
	//DEBUGLINE;
	SALT
	if (strlen(keychars) != 32) {
		return FALSE;
	}
	//DEBUGLINE;
	unsigned char key[16];
	char temp[3] = { 0 };
	char* check;
	SALT
	for (int i = 0; i < 16; i++) {
		memcpy(temp, &keychars[2 * i], 2);
		key[i] = strtol(temp, &check, 16);
#ifdef _DEBUG
		fprintf(stderr, "key[%d] = %02hhx\n", i, key[i]);
#endif
		if (check != &temp[2]) {
			return FALSE;
		}
	}
	//DEBUGLINE;
	SALT
	
	return doCheck(user, key);
}

BOOL doCheck(char user[], unsigned char* key) {

	SALT
	int read_write_pipe[2];
	pipe(read_write_pipe);

	pid_t parent_id = getppid();
	pid_t pid = fork();

	if(pid == 0){
		close(read_write_pipe[0]);
		pid_t child_pid = fork();

		if(child_pid == 0){
			SALT
			WORD buffer = 0;
			DWORD loop_size = 0;
			
			SALT
			for(int i = 0; i < 16; i++){
				buffer = 137;
				//printf("writing to buffer\n");
				write(read_write_pipe[1], &buffer, sizeof(buffer));
				}
			close(read_write_pipe[1]);
			_exit(0);
		}

		else{
			close(read_write_pipe[1]);
			struct timespec start;

			clock_gettime(CLOCK_REALTIME, &start);
			long start_time = start.tv_sec * 1000000000 + start.tv_nsec;
			
			SALT
			while(1) {
				//printf("current: %d original: %d \n", getppid(), parent_id);
				struct timespec now;

				clock_gettime(CLOCK_REALTIME, &now);

				long current_time = now.tv_sec * 1000000000 + now.tv_nsec;

				if(getppid() == 1 || getppid() == 5468){
					printf("parent closed. Closing child");
					_exit(0);
				}	
				if(current_time - start_time > 200000000) {
					printf("Debugger detected or program has ended. Closing\n");
					printf("current: %d original: %d \n", getppid(), parent_id);
					kill(parent_id, SIGKILL); 
					_exit(0);
			}

			usleep(50000);
			}
		}
		
	}
	SALT
	close(read_write_pipe[1]);
	EVP_MD_CTX* mdctx;
	BOOL bResult = FALSE;
	SALT
	mdctx = EVP_MD_CTX_create();
	if (mdctx == NULL) {
		return FALSE;
	}
	//DEBUGLINE;
	SALT
	bResult = EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	if (!bResult) {
		EVP_MD_CTX_destroy(mdctx);
		return FALSE;
	}
	//DEBUGLINE;
	SALT
	bResult = EVP_DigestUpdate(mdctx, user, strlen(user));
	if (!bResult) {
		EVP_MD_CTX_destroy(mdctx);
		return FALSE;
	}
	//DEBUGLINE;
	SALT
	BYTE MD5Data[20] = { 0 };
	SALT
	DWORD cbHash = sizeof(MD5Data);
	SALT
	write(read_write_pipe[1], &cbHash, sizeof(cbHash));
	bResult = EVP_DigestFinal_ex(mdctx, MD5Data, NULL);
	if (!bResult) {
		EVP_MD_CTX_destroy(mdctx);
		return FALSE;
	}
	//DEBUGLINE;
	SALT
	EVP_MD_CTX_destroy(mdctx);
	//DEBUGLINE;

#if 0
	printf("SHA1(user) = ");
	for (int i = 0; i < cbHash; i++) {
		printf("%02hhx", MD5Data[i]);
	}
	printf("\n");
#endif
	SALT
	WORD checkMD5 = 0;
	BYTE chain_value = 1;
	uint8_t shift = 0;
	WORD pipe_buffer = 0;
	SALT

	for (int i = 0; i < cbHash; i++) {
		checkMD5 += MD5Data[i] ^ chain_value;
		checkMD5 = checkMD5 * 107;
		chain_value = MD5Data[i]; 
	}
	SALT
	WORD checkKey = 0;
	chain_value = 1;

	for (int i = 0; i < 16; i++) {
		checkKey += key[i] ^ chain_value;
		read(read_write_pipe[0], &pipe_buffer, sizeof(pipe_buffer));

		checkKey = checkKey * pipe_buffer;
		chain_value = key[i];

	}
	close(read_write_pipe[0]);
	SALT

#ifdef _DEBUG
	printf("checkMD5 = %04x, checkKey = %04x\n", checkMD5, checkKey);
#endif

	return checkMD5 == checkKey;
}

int main(int argc, char* argv[])
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
#ifdef _DEBUG
	if (argc == 2) {
		unsigned char key[16];
		srand(time(NULL));
		for (int i = 0; i < 16; i++) {
			key[i] = rand();
		}
		while (1) {
			printf("Key: ");
			for (int i = 0; i < 16; i++) {
				printf("%02hhx", key[i]);
			}
			printf(": ");
			if (doCheck(argv[1], key)) {
				break;
			}
			for (int i = 15; i >= 0; i--) {
				key[i]++;
				if (key[i] != 0) break;
			}
			/*for (int i = 0; i < 16; i++) {
				key[i] = rand();
			}*/
		}
		printf("Found key: ");
		for (int i = 0; i < 16; i++) {
			printf("%02hhx", key[i]);
		}
		printf("\n");
		goto LAME_EXIT;
	}
#endif

	if (argc != 3) {
		fprintf(stderr, "Error: Please provide a username and key\n");
		exit(-1);
	}


	if (doCheckConvert(argv[1], argv[2])) {
		printf("You're winner!\n");
	}
	else {
		printf("You lose\n");
	}

#ifdef _DEBUG
LAME_EXIT:
#endif
	exit(0);
}

