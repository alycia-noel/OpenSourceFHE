/***************************************/
/* PALISADE BFVrns velocity calculator */
/* Author: Alycia N. Carey             */
/* Parts of code borrowed from:        */
/* demo-simple-exmple.cpp              */
/* final velocity = V_i + at   m/s     */
/***************************************/

#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
using namespace std;
using namespace lbcrypto;

void print(Plaintext v, int length)
{

    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++)
    {
        cout << setw(3) << right << v->GetPackedValue()[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v->GetPackedValue()[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	//Check to see if BFVrns is available
	#ifdef NO_QUADMATH
	cout << "This program cannot run due to BFVrns not being available for this architecture." 
	exit(0);
	#endif
	srand(time(NULL));

	/*****Set up the CryptoContext*****/
	clock_t cc_clock;
	cc_clock = clock();
	//Parameter Selection based on standard parameters from HE standardization workshop
  int plaintextModulus = 536903681;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;


	//Create the cryptoContext with the desired parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

	//Enable wanted functions
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****Generate Keys*****/ 
	clock_t key_clock;
	key_clock = clock();

	//Create the container for the public key   
	LPKeyPair<DCRTPoly> keyPair;

	//Generate the keyPair
	keyPair = cryptoContext->KeyGen();

	//Generate the relinearization key
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	key_clock = clock() - key_clock;

	/*****Encryption*****/
	clock_t enc_clock;
	enc_clock = clock();

	//Create and encode the plaintext vectors and variables
	int N = 2760; 
	vector<int64_t> initial_velocity; 
	vector<int64_t> times; 
	vector<int64_t> acc;   

	for(int i = 0; i < N; i++)
	{
		int64_t a = rand() % 25;
		acc.push_back(a);

		int64_t b = rand() % 50;
		initial_velocity.push_back(b);

		int64_t c = rand() % 30;
		times.push_back(c);
	}

	Plaintext plain_acc = cryptoContext->MakePackedPlaintext(acc);
	Plaintext plain_initial_vel = cryptoContext->MakePackedPlaintext(initial_velocity);
	Plaintext plain_times = cryptoContext->MakePackedPlaintext(times);

	//Encrypt the encodings
	auto enc_acc = cryptoContext->Encrypt(keyPair.publicKey, plain_acc);
	auto enc_initial_vel = cryptoContext->Encrypt(keyPair.publicKey, plain_initial_vel);
	auto enc_times = cryptoContext->Encrypt(keyPair.publicKey, plain_times);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
  clock_t eval_clock;
	eval_clock = clock();

	auto enc_acc_mult_times = cryptoContext->EvalMult(enc_acc, enc_times);                  //a*t
	auto enc_final_vel = cryptoContext->EvalAdd(enc_initial_vel, enc_acc_mult_times);			//V_i + at

	eval_clock = clock() - eval_clock;

	/*****Decryption*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_velocity;
	cryptoContext->Decrypt(keyPair.secretKey, enc_final_vel, &plain_final_velocity);

	dec_clock = clock() - dec_clock;

	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;

	cout << "Acceleration: " << endl;
	print(plain_acc, N);

	cout << "Initial Velocity: " << endl;
	print(plain_initial_vel, N);

	cout << "Time: " << endl;
	print(plain_times, N);

	cout << " Final Velocity: " << endl;
	print(plain_final_velocity, N);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;
}
