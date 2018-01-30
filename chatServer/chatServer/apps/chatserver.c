/*
Code modified by Abdallah Abu-Rezeq
*/

/* chatserver.c */

#include <stdlib.h>
#include <stdio.h>
#include <cnaiapi.h>
#include <time.h>

#define BUFFSIZE		256
#define KS_LENGTH		256
#define INPUT_PROMPT		"Input   > "
#define RECEIVED_PROMPT		"Received> "
#define RECEIVED_DATA		"Recieved Authentication Data...\n"

//Authentication
_Bool Authenticate(connection conn, char *buff, int, char *user);

// Original Chat Code
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
 * Program: chatserver
 * Purpose: wait for a connection from a chatclient & allow users to chat
 * Usage:   chatserver <appnum>
 *
 *-----------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	connection	conn;
	int		len;
	char	buff[BUFFSIZE];

	if (argc != 2) {
		(void) fprintf(stderr, "usage: %s <appnum>\n", argv[0]);
		exit(1);
	}

	(void) printf("Chat Server Waiting For Connection.\n");

	/* wait for a connection from a chatclient */

	conn = await_contact((appnum) atoi(argv[1]));
	if (conn < 0)
		exit(1);
	
	(void) printf("Chat Connection Established.\n");
	
	/*ESTABLISH RC4 TO ENCRYPT COMMUNICATION*/
		#define keyLength 5
		byte secretKey[keyLength] = { 25, 65, 201, 195, 100 };

		time_t seconds;
		seconds = time(NULL);
		int firstKeyNumber = (seconds / 3600) % KS_LENGTH;

		for (int i = 0; i < keyLength; i++) {
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

	(void)printf("Encrypted Connection Established.\n");


	_Bool Authenticated = 0;
	_Bool Identity = 0;
	char connectedUser [BUFFSIZE];

	/* iterate, reading from the client and the local user */

	while((len = recvln(conn, buff, BUFFSIZE)) > 0) {
		RC4_ENCRYPTandDECRYPT(buff, len - 1);

		if (Authenticated == 0) {
			(void)printf(RECEIVED_DATA);
			(void)fflush(stdout);
			
			if (Identity == 0) {
				buff[len - 1] = '\0';
				strcpy(connectedUser, buff);

				(void)printf("User ");
				(void)printf(connectedUser);
				(void)printf(" has connected\n");

				
				char servMsg[] = "Please Input Password.";
				int msgLen = sizeof(servMsg);
				servMsg[msgLen - 1] = '\n';

				RC4_ENCRYPTandDECRYPT(servMsg, msgLen - 1);
				(void)send(conn, servMsg, msgLen, 0);

				(void)printf("Authentication Reply Sent...\n");
				(void)fflush(stdout);

				Identity = 1;
			}
			else
				Authenticated = Authenticate(conn, buff, len, connectedUser);

		}
		else {
			(void)printf(RECEIVED_PROMPT);
			(void)fflush(stdout);
			(void)write(STDOUT_FILENO, buff, len);

			/* send a line to the chatclient */

			(void)printf(INPUT_PROMPT);
			(void)fflush(stdout);
			if ((len = readln(buff, BUFFSIZE)) < 1)
				break;
			buff[len - 1] = '\n';
			RC4_ENCRYPTandDECRYPT(buff, len - 1);
			(void)send(conn, buff, len, 0);
		}
	}

	/* iteration ends when EOF found on stdin or chat connection */

	(void) send_eof(conn);
	(void) printf("\nChat Connection Closed.\n\n");
	return 0;
}

_Bool Authenticate(connection conn, char *buff, int len, char *user) {
	/*
	Now design and implement a login protocol so that after the client connects to the server, the server authenticates the client first.
	Only after a client enters a correct password, the server can start chatting with the client.
	On the server side, there is an ASCII text file “passwd.txt”, where all users’ names and passwords are stored, in the format of “name::password”, one line for each user without spaces.
	*/

	_Bool validUser = 0;

	//Buffer to hold credentials from PW  file
	char credFromFile[BUFFSIZE];

	//remove \n char from buffer, otherwise comparison will fail with strstr()
	buff[len - 1] = '\0';


	//Open file containing user credentials
	FILE *inputFile;
	inputFile = fopen("passwd.txt", "r");

	if (inputFile == NULL) {
		perror("Error opening file");
		return validUser;
	}
	else{
		char *delimiter = "::"; //used in credential file seperates username::password

		//Authentication Loop
		while (fgets(credFromFile, BUFFSIZE, inputFile) != NULL){
			char *username = strtok(credFromFile, delimiter);
			char *password = strtok(NULL, delimiter);

			//Need to remove \n from every password otherwise comparison fails
			int password_len = strlen(password);
			if (password[password_len - 1] == '\n'){
				password[password_len - 1] = '\0';
			}

			if (strcmp(username, user) == 0){
				if ((strcmp(password, buff) == 0)) {
					validUser = 1;
				}
			}
		}
	}


	//return bool and message based on if valid user was found or not
	if (validUser == 0) {
		char servMsg[] = "Invalid password , please input password again.";
		int msgLen = sizeof(servMsg);
		servMsg[msgLen - 1] = '\n';

		RC4_ENCRYPTandDECRYPT(servMsg, msgLen - 1);
		(void) send(conn, servMsg, msgLen, 0);

		(void) printf("Authentication Reply Sent...\n");
		(void) fflush(stdout);

		fclose(inputFile);
		return validUser;
	}
	else if(validUser == 1) {
		char servMsg[] = "Credential valid! Welcome.";
		int msgLen = sizeof(servMsg);
		servMsg[msgLen - 1] = '\n';

		RC4_ENCRYPTandDECRYPT(servMsg, msgLen - 1);
		(void) send(conn, servMsg, msgLen, 0);

		(void) printf("Authentication Reply Sent...\n");
		(void) fflush(stdout);

		fclose(inputFile);
		return validUser;
		}

	return validUser;
	fclose(inputFile);
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

	for (int i = 0; i < length; i++) {
		keyByte = RC4_STREAM();
		inputByte = input[i];

		input[i] = inputByte ^ keyByte;
	}
}

