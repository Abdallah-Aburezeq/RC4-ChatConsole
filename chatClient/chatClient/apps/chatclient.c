/* chatclient.c */

#include <stdlib.h>
#include <stdio.h>
#include <cnaiapi.h>
#include <time.h>

#define BUFFSIZE		256
#define KS_LENGTH		256
#define INPUT_PROMPT		"Input   > "
#define RECEIVED_PROMPT		"Received> "

int recvln(connection, char *, int);
int readln(char *, int);

/*RC4 ENCRYPTION PROTOTYPES*/
typedef unsigned char byte;
byte KEY_STREAM[KS_LENGTH] = { 0 };
int KS_currentIndex = 0; //Needed in order to keep track of RC4_STREAM progress, otherwise it will be deleted outside function scope
int KS_currentRandom = 0; //same as currentIndex

void RC4_INIT(int, byte *secretKey);
byte RC4_STREAM();
void RC4_ENCRYPTandDECRYPT(char *input, int length);
void RC4_swap(byte *, int, int);
/*END OF RC4 PROTOTYPES*/

/*-----------------------------------------------------------------------
 *
 * Program: chatclient
 * Purpose: contact a chatserver and allow users to chat
 * Usage:   chatclient <compname> <appnum>
 *
 *-----------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	computer	comp;
	connection	conn;
	char		buff[BUFFSIZE];
	int		len;

	if (argc != 3) {
		(void) fprintf(stderr, "usage: %s <compname> <appnum>\n",
			       argv[0]);
		exit(1);
	}

	/* convert the compname to binary form comp */

	comp = cname_to_comp(argv[1]);
	if (comp == -1)
		exit(1);

	/* make a connection to the chatserver */

	conn = make_contact(comp, (appnum) atoi(argv[2]));
	if (conn < 0) 
		exit(1);

	(void) printf("Chat Connection Established.\n");
	
	/*ESTABLISH RC4 TO ENCRYPT COMMUNICATION*/
		#define keyLength 5
		byte secretKey[keyLength] = { 0, 0, 0, 0, 0 };

		time_t seconds;
		seconds = time(NULL);
		int firstKeyNumber = (seconds / 3600) % KS_LENGTH;

		for (int i = 0; i < keyLength ; i++){
			secretKey[i] = firstKeyNumber + i;
		}

		RC4_INIT(keyLength, secretKey);

		//Discarding the first 3072 stream bytes for greater security
		int bytesDiscarded = 0;
		while (bytesDiscarded < 3072) {
			RC4_STREAM();
			bytesDiscarded++;
		}
	/*END OF ENCRYPTION INITIALIZATION*/

	(void)printf("Encrypted Communication Established.\n");

	(void) printf("Input Username)> ");
	(void) fflush(stdout);

	/* iterate, reading from local user and then from chatserver */

	while((len = readln(buff, BUFFSIZE)) > 0) {
		buff[len - 1] = '\n';
		RC4_ENCRYPTandDECRYPT(buff, len - 1);
		(void) send(conn, buff, len, 0);

		/* receive and print a line from the chatserver */
		if ((len = recvln(conn, buff, BUFFSIZE)) < 1)
			break;
		(void) printf(RECEIVED_PROMPT);
		(void) fflush(stdout);
		RC4_ENCRYPTandDECRYPT(buff, len - 1);
		(void) write(STDOUT_FILENO, buff, len);

		(void) printf(INPUT_PROMPT);
		(void) fflush(stdout);
	}

	/* iteration ends when stdin or the connection indicates EOF */

	(void) printf("\nChat Connection Closed.\n");
	(void) send_eof(conn);
	exit(0);
}

void RC4_swap(byte *inputArray, int index1, int index2) {
	byte temp = inputArray[index1];

	inputArray[index1] = inputArray[index2];
	inputArray[index2] = temp;
}

void RC4_INIT(int keyLen, byte *key) {
	//Initialize with 0 to 255 array
	for (int i = 0; i < KS_LENGTH; i++) {
		KEY_STREAM[i] = i;
	}

	//Initial permutation based on user key values
	int randomIndex = 0;
	for (int i = 0; i < KS_LENGTH; i++) {
		randomIndex = (randomIndex + KEY_STREAM[i] + key[i % keyLen]) % KS_LENGTH;

		RC4_swap(KEY_STREAM, i, randomIndex);
	}
}

byte RC4_STREAM() {
	//Here the RC4 stream progresses after the intial RC4_INIT, continues to swap and also returns 1 byte stream.

	KS_currentIndex = (KS_currentIndex + 1) % KS_LENGTH;
	KS_currentRandom = (KS_currentRandom + KEY_STREAM[KS_currentIndex]) % KS_LENGTH;

	RC4_swap(KEY_STREAM, KS_currentIndex, KS_currentRandom);

	int returnByteIndex = (KEY_STREAM[KS_currentIndex] + KEY_STREAM[KS_currentRandom]) % KS_LENGTH;
	byte encryptionByte = KEY_STREAM[returnByteIndex];

	return encryptionByte;
}

void RC4_ENCRYPTandDECRYPT(char *input, int length) {
	byte inputByte;
	byte keyByte;
	byte sendByte;

	for (int i = 0; i < length; i++){
		keyByte = RC4_STREAM();
		inputByte = input[i];
		
		sendByte = inputByte ^ keyByte;
		
		input[i] = sendByte;
	}
}

