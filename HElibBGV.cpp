/***************************************/
/* HElib BGV velocity calculator       */
/* Author: Alycia N. Carey             */
/* Parts of code borrowed from:        */
/* BGV_general_example.cpp             */
/* final velocity = V_i + at   m/s     */
/***************************************/
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <helib/helib.h>

using namespace std;
using namespace helib;

void print(vector<long> v, long length)
{

    int print_size = 20;
    int end_size = 2;

    cout << endl;
    cout << "    [";

    for (int i = 0; i < print_size; i++)
    {
        cout << setw(3) << right << v[i] << ",";
    }

    cout << setw(3) << " ...,";

    for (int i = length - end_size; i < length; i++)
    {
        cout << setw(3) << v[i] << ((i != length - 1) ? "," : " ]\n");
    }
    
    cout << endl;
}

int main()
{
	srand(time(NULL));
	/*****Set Parameters*****/
	clock_t cc_clock;
	cc_clock = clock();

	unsigned long prime_mod      = 55001;
	unsigned long cyc_poly       = 32109;
	unsigned long bits_mod_chain = 300;
	unsigned long key_switch_col = 2;

	//Generate context and add primes to chain
	Context context(cyc_poly, prime_mod, 1);
	buildModChain(context, bits_mod_chain, key_switch_col);
	std::cout << "Security: " << context.securityLevel() << std::endl;

	cc_clock = clock() - cc_clock;

	//Key Generation
	clock_t key_clock;
	key_clock = clock();

	SecKey secret_key(context);
	secret_key.GenSecKey();
	addSome1DMatrices(secret_key);
	PubKey& public_key = secret_key;

	const EncryptedArray& ea = *(context.ea);
	long num_slots = ea.size(); //24
	std::cout << "Number of slots: " << num_slots << std::endl;

	key_clock = clock() - key_clock;

	//Encryption
	clock_t enc_clock;
	enc_clock = clock();

	vector<long> initial_velocity;
	vector<long> times;
	vector<long> acc;

	for(int i = 0; i < num_slots; i++)
	{
		int64_t a = rand() % 25;
		acc.push_back(a);

		int64_t b = rand() % 50;
		initial_velocity.push_back(b);

		int64_t c = rand() % 30;
		times.push_back(c);
	}

	Ctxt enc_initial_vel(public_key);
	Ctxt enc_times(public_key);
	Ctxt enc_acc(public_key);
	Ctxt enc_final_vel(public_key);
	ea.encrypt(enc_initial_vel, public_key, initial_velocity);
	ea.encrypt(enc_times, public_key, times);
	ea.encrypt(enc_acc, public_key, acc);

	enc_clock = clock() - enc_clock;

	//Evaluation
	clock_t eval_clock;
	eval_clock = clock();

	enc_final_vel += enc_acc;
	enc_final_vel *= enc_times;
	enc_final_vel += enc_initial_vel;

	eval_clock = clock() - eval_clock;

	//Decrypt
	clock_t dec_clock;
	dec_clock = clock();

	vector<long> final_vel;
	ea.decrypt(enc_final_vel, secret_key, final_vel);

	dec_clock = clock() - dec_clock;
	/*****Print*****/
	cout << "Starting the velocity caluculator with " << num_slots << " instances. "<< endl << endl;

	cout << "Acceleration: " << endl;
	print(acc, num_slots);

	cout << "Initial Velocity: " << endl;
	print(initial_velocity, num_slots);

	cout << "Time: " << endl;
	print(times, num_slots);

	cout << "Final Velocity: " << endl;
	print(final_vel, num_slots);

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;
	return 0;

}
