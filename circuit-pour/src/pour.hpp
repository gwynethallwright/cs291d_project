
#include <string>

extern "C"
{
    void c_generate_proof(int gen_key, int v_value_pub, int v_coin_new_1_value, int v_coin_new_2_value, int v_coin_old_1_value, int v_coin_old_2_value);
    int c_verify_proof(int v_value_pub);
}
void generate_proof(int gen_key, int v_value_pub, int v_coin_new_1_value, int v_coin_new_2_value, int v_coin_old_1_value, int v_coin_old_2_value);
bool verify_proof(int v_value_pub);