#include <iostream>

#include "pour.hpp"

int main(int argc, char **argv){
    if(argc <= 1){
        std::cout << "main(): starting generate_proof" << std::endl;
        generate_proof("",1,3,1,2,3);
    } else {
        int v_value_pub = atoi(argv[1]);
        std::cout << "main(): starting verify_proof with v_value_pub=" << v_value_pub << std::endl;
        verify_proof("", v_value_pub);
    }
    return 0;
}