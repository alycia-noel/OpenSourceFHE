/***************************************/
/* PALISADE BGV velocity calculator    */
/* Author: Alycia N. Carey             */
/* Parts of code borrowed from:        */
/* demo-packing.cpp                    */
/* final velocity = V_i + at   m/s     */
/***************************************/

#include "palisade.h"
#include <iostream>
#include <vector>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <random>
#include <iterator>


using namespace std;
using namespace lbcrypto;

int main()
{
	/*****Parameter Generation*****/
	clock_t cc_clock;
	cc_clock = clock();

	usint m = 22;
	PlaintextModulus p = 2333;
	BigInteger modulusP(p);
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, encodingParams, 11, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	cc_clock = clock() - cc_clock;

	/*****KeyGen*****/
	clock_t key_clock;
	key_clock = clock();

	LPKeyPair<Poly> kp = cc->KeyGen();
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	key_clock = clock() - key_clock;

	/*****Encode and Encrypt*****/
	clock_t enc_clock;
	enc_clock = clock();

	std::vector<int64_t> initial_velocity = { 1,2,3,4,5,6,7,8};
	Plaintext plain_initial_vel = cc->MakePackedPlaintext(initial_velocity);

	std::cout << "Initial Velocity \n\t" << initial_velocity << std::endl;

	std::vector<int64_t> times = { 10, 14, 24, 23, 18, 9, 13, 7};
	Plaintext plain_times = cc->MakePackedPlaintext(times);

	std::cout << "Times \n\t" << times << std::endl;

	std::vector<int64_t> acc = { 1,2,3,2,1,2,1,2};
	Plaintext plain_acc = cc->MakePackedPlaintext(acc);

	std::cout << "Acceleration \n\t" << acc << std::endl;

	auto enc_initial_vel = cc->Encrypt(kp.publicKey, plain_initial_vel);
	auto enc_times = cc->Encrypt(kp.publicKey, plain_times);
	auto enc_acc = cc->Encrypt(kp.publicKey, plain_acc);

	enc_clock = clock() - enc_clock;

	/*****Evaluate*****/
	clock_t eval_clock;
	eval_clock = clock();

	auto enc_final_vel = cc->EvalMult(enc_times, enc_acc);
	enc_final_vel = cc->EvalAdd(enc_final_vel, enc_initial_vel);
	
	eval_clock = clock() - eval_clock;
	
	/*****Decrypt*****/
	clock_t dec_clock;
	dec_clock = clock();

	Plaintext plain_final_vel;

	cc->Decrypt(kp.secretKey, enc_final_vel, &plain_final_vel);
	
	dec_clock = clock() - dec_clock;

	/*****Print*****/
	std::cout << "Final Velocity \n\t" << plain_final_vel << std::endl;

	cout << "Times:" <<endl;
	cout << "Parameter Generation  : " << ((float)cc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Key Generation        : " << ((float)key_clock)/CLOCKS_PER_SEC << endl;
	cout << "Encryption            : " << ((float)enc_clock)/CLOCKS_PER_SEC << endl;
	cout << "Evaluation (v_i + at) : " << ((float)eval_clock)/CLOCKS_PER_SEC << endl;
	cout << "Decryption            : " << ((float)dec_clock)/CLOCKS_PER_SEC << endl;

}

