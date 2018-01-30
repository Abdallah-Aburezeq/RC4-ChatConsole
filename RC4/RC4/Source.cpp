/*
RC4 Implementation by Abdallah Rami Abu-Rezeq

For Introduction to Network Security (CRN12275) with Instructor: Dr. Shengli Yuan

Completed 10/1/2017
*/


#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
using namespace std;

//MISC
typedef unsigned char byte;


//GLOBAL VARIABLES
const int KS_LENGTH = 256;
byte KEY_STREAM[KS_LENGTH] = {0};
int KS_currentIndex = 0; //Needed in order to keep track of RC4_STREAM progress, otherwise it will be deleted outside function scope
int KS_currentRandom = 0; //same as currentIndex


//FUNCTION PROTOTYPES
void RC4_INIT(int, byte *);
byte RC4_STREAM();
void RC4_ENCRYPT(istream&, ostream&);
void RC4_DECRYPT(istream&, ostream&);
void swap(byte *, int, int);

//MAIN FUNCTION
int main (){
	int keyLength = 0;
	byte *secretKey = nullptr;

	cout << "How many bytes (5 to 32) do you want the secret key?: ";
	cin >> keyLength;
	if (keyLength <5 || keyLength > 32){
		cout << "\nIncompatible Key Length. CLOSING";
		system("pause");
		return 1;
	}

	secretKey = new byte[keyLength];

	cout << "Please enter " << keyLength << " numbers (0 to 255) sepreated by spaces, which will act as your secret key: ";
	
	for (int i = 0; i < keyLength; i++){
		int keyInput;
		cin >> keyInput;

		if ( (keyInput < 0) || (keyInput > 256) ) {
			cout << "\nIncompatible key input. CLOSING";
			system("pause");
			delete [] secretKey;
			secretKey = nullptr;
			return 1;
		}

		else{
			secretKey[i] = keyInput;

			//Uncomment to view secretKey char
			//cout << "\n valid input: " << secretKey[i] << endl;
		}
	}

	//Initialize the cipher stream based on the users input secretKey
	RC4_INIT(keyLength, secretKey);

	//Discarding the first 3072 stream bytes for greater security
	int bytesDiscarded = 0;
	while (bytesDiscarded < 3072){
		RC4_STREAM();
		bytesDiscarded++;
	}

	//Get file to encypt/decrpy  (.TXT ONLY)
	cout << "Please enter filename(.txt) to encypt/decypt: ";
	string fileName;
	cin >> fileName;

	ifstream inputFile(fileName);
	ofstream outputFile("OUTPUT_" + fileName);

	if (inputFile.fail()){
		cout << "Error opening file. CLOSING";
		delete[] secretKey;
		secretKey = nullptr;
		system("pause");
		return 1;
	}
	else{
		cout << "Would you like to-- "
			<< "\n1) Encrypt"
			<< "\n2) Decrypt";

		int selection = 0;
		while ((selection <= 0) || (selection >= 3)) {
			cout << "\nSelect number: ";
			cin >> selection;
		}
		
		if (selection == 1){
			RC4_ENCRYPT(inputFile, outputFile);
		}
		else if (selection == 2){
			RC4_DECRYPT(inputFile, outputFile);
		}
		else {
			cout << "PROGRAM ERROR. CLOSING";
			delete[] secretKey;
			secretKey = nullptr;
			system("pause");
			return 1;
		}
	}


	cout << "\nEncryption/decryption of file was succesful. CLOSING. \n";
	inputFile.close();
	outputFile.close();
	system("pause");

	delete[] secretKey;
	secretKey = nullptr;
	return 0;
}

void RC4_INIT(int keyLen, byte *key) {
	//Initialize with 0 to 255 array
	for (int i = 0; i < KS_LENGTH; i++){
		KEY_STREAM[i] = i;
	}

	//Initial permutation based on user key values
	int randomIndex = 0;
	for (int i = 0; i < KS_LENGTH; i++){
		randomIndex = (randomIndex + KEY_STREAM[i] + key[i % keyLen]) % KS_LENGTH;

		swap(KEY_STREAM, i, randomIndex);
	}
}

void swap(byte *inputArray, int index1, int index2) {
	byte temp = inputArray[index1];

	inputArray[index1] = inputArray[index2];
	inputArray[index2] = temp;
}

byte RC4_STREAM(){
	//Here the RC4 stream progresses after the intial RC4_INIT, continues to swap and also returns 1 byte stream.

	KS_currentIndex = (KS_currentIndex + 1) % KS_LENGTH;
	KS_currentRandom = (KS_currentRandom + KEY_STREAM[KS_currentIndex]) % KS_LENGTH;

	swap(KEY_STREAM, KS_currentIndex, KS_currentRandom);

	int returnByteIndex = (KEY_STREAM[KS_currentIndex] + KEY_STREAM[KS_currentRandom]) % KS_LENGTH;
	byte encryptionByte = KEY_STREAM[returnByteIndex];

	return encryptionByte;
}

void RC4_ENCRYPT(istream &inputFile, ostream &outputFile) {
	byte inputByte;
	byte keyByte;

	inputFile >> noskipws;
	while (inputFile >> inputByte) {
		keyByte = RC4_STREAM();

		//byte outputChar = (keyByte ^ inputByte);
		outputFile << showbase << internal << setfill('0') << hex << setw(5) << (keyByte ^ inputByte) << " "; //final space needed to decrpt, in order to tell where one hex number starts and stops
	}
}

void RC4_DECRYPT(istream &inputFile, ostream &outputFile) {
	//get hex chars, process, and output to file
	
	byte inputByte;
	byte keyByte;

	//int can be intialized with hex input, so first the hex number is retrieved by inputFile then converted to decimal int
	int hexInput;
	while (inputFile >> hex >> setw(4) >> hexInput) {
		keyByte = RC4_STREAM();

		//transfer valid decimal number into char byte form
		inputByte = hexInput;

		byte outputChar = (keyByte ^ inputByte);
		outputFile << outputChar;
	}
}