/****************************************/
/* SEAL BFV batched velocity calculator */
/* Author: Alycia N. Carey              */
/* Parts of code borrowed from:         */
/* 1_bfv_basics.cpp and 2_encoders.cpp  */
/* final velocity = V_i + at   m/s      */
/****************************************/

#include <iostream>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include "seal/seal.h"
#include "examples.h"

using namespace std;
using namespace seal;

int main()
{
	/*****Choose Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();

	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

	//Enable batching
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	auto context = SEALContext::Create(parms);
	//print_parameters(context);
	
	//Verify that batching is enabled
	//auto qualifiers = context->first_context_data()->qualifiers();
	//cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

	/*****Generate keys and functions*****/
	clock_t key_clock;
	key_clock = clock();

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
	RelinKeys relin_keys = keygen.relin_keys();

	key_clock = clock() - key_clock;

	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);

	//Set up batch encoder
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;
	
	
	cc_clock = clock() - cc_clock - key_clock;
	
	clock_t enc_clock;
	enc_clock = clock();
	//Generate the matrices of values 
	int N = 8192; //or 100 or 1000
	vector<uint64_t> initial_velocity(slot_count, 0ULL);    
	vector<uint64_t> times(slot_count, 0ULL);               
	vector<uint64_t> acc(slot_count, 0ULL);                 

	for(int r = 0; r < 2; r++)
	{
		for(int c = 0; c < N/2; c++) 
		{
			unsigned long long int a = rand() % 250;
			acc[r*row_size + c] = a;

			unsigned long long int b = rand() % 500;
			initial_velocity[r*row_size + c] = b;

			unsigned long long int d = rand() % 300;
			times[r*row_size + c] = d;
		}
	}
	
	
	
	/*****Encode*****/
	Plaintext plain_initial_vel;
	Plaintext plain_times;
	Plaintext plain_acc;

	batch_encoder.encode(initial_velocity, plain_initial_vel);
	batch_encoder.encode(times, plain_times);
	batch_encoder.encode(acc, plain_acc);

	/*****Encrypt*****/
	Ciphertext enc_initial_vel;
	Ciphertext enc_times;
	Ciphertext enc_acc;

	encryptor.encrypt(plain_initial_vel, enc_initial_vel);
	encryptor.encrypt(plain_times, enc_times);
	encryptor.encrypt(plain_acc, enc_acc);

	enc_clock = clock() - enc_clock;

	/*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

	Ciphertext enc_final_vel;

	evaluator.multiply(enc_acc, enc_times, enc_final_vel);
	evaluator.add_inplace(enc_final_vel, enc_initial_vel);

	eval_clock = clock() - eval_clock;

	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_vel;

	decryptor.decrypt(enc_final_vel, plain_final_vel);
	
	dec_clock = clock() - dec_clock;

	/*****Decode*****/
	vector<uint64_t> final_vel;
	batch_encoder.decode(plain_final_vel, final_vel);
	
	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;
	cout << "Acceleration: " << endl;
	print_matrix(acc, row_size);

	cout << "Initial Velocity: " << endl;
	print_matrix(initial_velocity, row_size);

	cout << "Time: " << endl;
	print_matrix(times, row_size);

	cout << " Final Velocity: " << endl;
	print_matrix(final_vel, row_size);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

	return 0;
}
