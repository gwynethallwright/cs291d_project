#include <iostream>

#include "pour.hpp"

int main(int argc, char **argv){
    if(argc <= 1){ 
        generate_proof(1,0,0,0,0,0);
    } else if(argc == 6){
        std::cout << "main(): starting generate_proof" << std::endl;
        generate_proof(0,atoi(argv[1]),atoi(argv[2]),atoi(argv[3]),atoi(argv[4]),atoi(argv[5]));
    } else if(argc == 2){
        int v_value_pub = atoi(argv[1]);
        std::cout << "main(): starting verify_proof with v_value_pub=" << v_value_pub << std::endl;
        verify_proof(v_value_pub);
    }
    return 0;
}