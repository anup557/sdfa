/* gist: code for ... cipher in C. The oracle has passed test vectors given in */ 
/* "give paper link" (page: ...). */
/* ------------------------------------------------------------------------------------------ */

#include <stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "/home/anup/Dropbox/lit_survey/000_prog/others/necessary_files/my_lib.h"

#define state_size 128
#define key_size 128

int main(){
    uint64_t *msg = mem_alloc(state_size);
    uint64_t *key = mem_alloc(key_size);

    insert(msg, 0xfc7e61fee3d58730, 0x8ca7bc594ebf3244);

    /* oracle(msg, key); */
    print(msg, state_size);

    printf("[");
    for (int i=0; i<31; i++){
        printf("%ld, ", msg[1]&0xf);
        shift(msg, 4, 128, "right");
    }
    printf("%ld]", msg[1]&0xf);
    
    }
