/***************************************/
/* PALISADE CKKS velocity calculator   */
/* Author: Alycia N. Carey             */
/* Parts of code borrowed from:        */
/* demo-simple-real-numbers.cpp        */
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
        cout << setw(3) << right << v->GetCKKSPackedValue()[i].real() << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v->GetCKKSPackedValue()[i].real() << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	/*****Setup CryptoContext*****/
	clock_t cc_clock;
	cc_clock = clock();

	uint32_t multDepth = 1;
	uint32_t scaleFactorBits = 50;
	uint32_t batchSize = 8192; //num plaintext slots
	SecurityLevel securityLevel = HEStd_128_classic;

	CryptoContext<DCRTPoly> cc =
			CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
			   multDepth,
			   scaleFactorBits,
			   batchSize,
			   securityLevel);

	//cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << endl << endl;

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

	auto keys = cc->KeyGen();
	cc->EvalMultKeyGen(keys.secretKey);
	cc->EvalAtIndexKeyGen(keys.secretKey, { 1, -2 });

	key_clock = clock() - key_clock;

	/*****Encoding*****/

	clock_t enc_clock;
	enc_clock = clock();

	int N = 2760; 
	vector<complex<double>> initial_velocity; 
	vector<complex<double>> times; 
	vector<complex<double>> acc;   

	for(int i = 0; i < N; i++)
	{
		complex<double> a = (rand()/(double(RAND_MAX))*25);
		acc.push_back(a);

		complex<double> b = (rand()/(double(RAND_MAX))*50);
		initial_velocity.push_back(b);

		complex<double> c = (rand()/(double(RAND_MAX))*30);
		times.push_back(c);
	}
	

	Plaintext plain_initial_vel = cc->MakeCKKSPackedPlaintext(initial_velocity);
	Plaintext plain_times = cc->MakeCKKSPackedPlaintext(times);
	Plaintext plain_acc = cc->MakeCKKSPackedPlaintext(acc);

	// Encrypt the encoded vectors
	auto enc_times = cc->Encrypt(keys.publicKey, plain_times);
	auto enc_acc = cc->Encrypt(keys.publicKey, plain_acc);
	auto enc_initial_vel = cc->Encrypt(keys.publicKey, plain_initial_vel);

	enc_clock = clock() - enc_clock;

	/*****Evaluation*****/
	clock_t eval_clock;
	eval_clock = clock();

	auto cMult = cc->EvalMult(enc_times, enc_acc);
	auto cAdd = cc->EvalAdd(cMult, enc_initial_vel);

	eval_clock = clock() - eval_clock;

	/*****Decryption and output*****/
	clock_t dec_clock;
	dec_clock = clock();
	
	Plaintext plain_final_vel;
	cout.precision(6);

	cc->Decrypt(keys.secretKey, cAdd, &plain_final_vel);

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
	print(plain_final_vel, N);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

	return 0;
}

