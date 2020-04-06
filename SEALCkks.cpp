/****************************************/
/* SEAL CKKS velocity calculator        */
/* Author: Alycia N. Carey              */
/* Parts of code borrowed from:         */
/* 4_CKKS_basics.cpp                    */
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
	/*****Set Parameters and Context*****/
	clock_t cc_clock;
	cc_clock = clock();

	EncryptionParameters parms(scheme_type::CKKS);

	 size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 40, 40, 60 }));

	double scale = pow(2.0, 40);

    auto context = SEALContext::Create(parms);

	/*****Key Generation*****/
	clock_t key_clock;
	key_clock = clock();

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
	cc_clock = clock() - cc_clock - key_clock;

	/*****Encode and Encrypt*****/
	clock_t enc_clock;
	enc_clock = clock();

    int N = 2760; 
	vector<double> initial_velocity; 
	vector<double> times; 
	vector<double> acc;   

	for(int i = 0; i < N; i++)
	{
		double a = (rand()/(double(RAND_MAX))*25);
		acc.push_back(a);

		double b = (rand()/(double(RAND_MAX))*50);
		initial_velocity.push_back(b);

		double c = (rand()/(double(RAND_MAX))*30);
		times.push_back(c);
	}



    Plaintext plain_initial_vel, plain_times, plain_acc;
    encoder.encode(initial_velocity, scale, plain_initial_vel);
    encoder.encode(times, scale, plain_times);
    encoder.encode(acc, scale, plain_acc);

    Ciphertext enc_initial_vel, enc_times, enc_acc;
    encryptor.encrypt(plain_initial_vel, enc_initial_vel);
	encryptor.encrypt(plain_times, enc_times);
	encryptor.encrypt(plain_acc, enc_acc);

	enc_clock = clock() - enc_clock;

    /*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

    Ciphertext enc_final_vel;

    evaluator.multiply(enc_acc, enc_times, enc_final_vel);
	evaluator.relinearize_inplace(enc_final_vel, relin_keys);
	evaluator.rescale_to_next_inplace(enc_final_vel);
	
	enc_final_vel.scale() = pow(2.0,40);
	enc_initial_vel.scale() = pow(2.0,40);

	parms_id_type last_parms_id = enc_final_vel.parms_id();
	evaluator.mod_switch_to_inplace(enc_initial_vel, last_parms_id);
	evaluator.add_inplace(enc_final_vel, enc_initial_vel);

	eval_clock = clock() - eval_clock;

	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_vel;
	decryptor.decrypt(enc_final_vel, plain_final_vel);

	dec_clock = clock() - dec_clock;

	/*****Decode*****/
	vector<double> final_vel;
	encoder.decode(plain_final_vel, final_vel);

	/*****Print*****/
	cout << "Starting the velocity caluculator with " << N << " instances. "<< endl << endl;
	cout << "Acceleration: " << endl;
	print_vector(acc, 10, 4);

	cout << "Initial Velocity: " << endl;
	print_vector(initial_velocity, 10, 4);

	cout << "Time: " << endl;
	print_vector(times, 10, 4);

	cout << " Final Velocity: " << endl;
	print_vector(final_vel, 10, 4);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

}
