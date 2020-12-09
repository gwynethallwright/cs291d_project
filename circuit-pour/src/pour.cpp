#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"

#include "util.hpp"

using namespace libsnark;
using namespace std;

int main(){
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
    default_r1cs_ppzksnark_pp::init_public_params();

    protoboard<FieldT> pb;

    // x_pub = (rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, h_sig, h1, h2)
    // a_private = (path1, path2, coin_old_1, coin_old_2,
    //              addr_old_sk_1, addr_old_sk_2, coin_new_1, coin_new_2)

    pb_variable<FieldT> rt, sn_old_1, sn_old_2, cm_new_1, cm_new_2, value_pub, h_sig, h1, h2;

    //TODO: somehow figure out a way to dump the whole tree here
    rt.allocate(pb, "rt");
    sn_old_1.allocate(pb, "sn_old_1");
    sn_old_2.allocate(pb, "sn_old_2");
    cm_new_1.allocate(pb, "cm_new_1");
    cm_new_2.allocate(pb, "cm_new_2");
    value_pub.allocate(pb, "value_pub");
    h_sig.allocate(pb, "h_sig");
    h1.allocate(pb, "h1");
    h2.allocate(pb, "h2");

    pb_variable<FieldT> path1, path2, coin_old_1, coin_old_2, addr_old_sk_1, addr_old_sk_2, coin_new_1, coin_new_2;

    path1.allocate(pb, "path1");
    path2.allocate(pb, "path2");
    coin_old_1.allocate(pb, "coin_old_1");
    coin_old_2.allocate(pb, "coin_old_2");
    addr_old_sk_1.allocate(pb, "addr_old_sk_1");
    addr_old_sk_2.allocate(pb, "addr_old_sk_2");
    coin_new_1.allocate(pb, "coin_new_1");
    coin_new_2.allocate(pb, "coin_new_2");

    pb.set_input_sizes(9);

    //requirement 1.a
    //The coin commitment cm^old_i of c^old_i appears on the ledger, 
    //i.e., pathi is a valid authentication path for leaf cm^old_i with respect to root rt, in a CRH-based Merkle tree.

    //requirement 1.b
    //The address secret key a^old_sk,i matches the address public key of coldi , 
    //i.e., a^old_pk,i = PRF^{addr}_{a^old_sk,i}(0)
    
    //requirement 1.c
    //The serial number sn^old_i of c^old_i is computed correctly, 
    //i.e., sn^old_i = PRF^sn_{a^old_sk,i}(rho^old_i)
    
    //requirement 1.d & 1.e
    //The coin c^old_i and c^new_i is well formed
    //https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/gadgets/hashes/sha256/tests/test_sha256_gadget.cpp
    //k := COMM_r(a_pk||rho)
    digest_variable<FieldT> a_pk(pb, SHA256_digest_size, "a_pk");
    digest_variable<FieldT> rho(pb, SHA256_digest_size, "rho");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, a_pk, rho, output, "f");
    f.generate_r1cs_constraints();
    printf("Number of constraints for sha256_two_to_one_hash_gadget: %zu\n", pb.num_constraints());

    const libff::bit_vector left_bv, right_bv, hash_bv;
    //TODO: initalize bit_vectors

    a_pk.generate_r1cs_witness(left_bv);
    rho.generate_r1cs_witness(right_bv);

    f.generate_r1cs_witness();
    output.generate_r1cs_witness(hash_bv);

    assert(pb.is_satisfied());

    //cm := COMM_s(v||k)
    

    //requirement 1.f
    //The address secret key a^old_sk,i ties h_Sig to h_i

    //requirement 2
    //Balance is preserved
    
    // coin_new_1_value + coin_new_2_value + value_pub = coin_old_1_value + coin_old_2_value
    pb_variable<FieldT> coin_new_12_value, new_value, coin_old_12_value;
    coin_new_12_value.allocate(pb, "coin_new_12_value");
    new_value.allocate(pb, "new_value");
    coin_old_12_value.allocate(pb, "coin_old_12_value");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(coin_new_1_value + coin_new_2_value, 1, coin_new_12_value));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(coin_new_12_value + value_pub, 1, new_value));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(coin_old_1_value + coin_old_2_value, 1, coin_old_12_value));
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(new_value, 1, coin_old_12_value));
    
    // coin_old_1_value >= 0

    // coin_old_2_value >= 0

    // coin_old_1_value + coin_old_2_value <= v_max


    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    pb.val(coin_new_1_value) = 35;

    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

    return 0;
}