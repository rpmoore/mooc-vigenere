#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <malloc.h>

#define MAX_BUF 1000
#define MAX_KEY_SIZE 13

double frequency_list[26] = {8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074};

size_t loadBuffer(unsigned char *buff) {
    FILE *fpIn;
    size_t bytesRead = 0;
    int i = 0;
    unsigned char readByte;
    fpIn = fopen("ciphertext.txt", "r");

    if (fpIn == NULL) {
        fprintf(stderr, "Failed to open cipher text file\n");
        exit(1);
    }

    while(fscanf(fpIn, "%2hhX", &readByte) != EOF) {
         buff[i] = readByte;
         bytesRead++;
         i++;
    } 

    fclose(fpIn);
    return bytesRead;
}

void print_buffer(const unsigned char* buff, size_t buff_size) {
    size_t i;

    for(i = 0; i < buff_size; i++) {
        printf("%02X", buff[i]);
    }
    printf("\n");
}

bool valid_char(unsigned char c) {
    /*
    if (isalpha(c) || ispunct(c)) return true;
    
    return false;
    */
    if (37 < c && c < 127) return true;
    
    return false;
}

int max_frequency(double* frequency_values) {
    int i;
    double max_value = frequency_values[0];
    int max_index= 0;

    for (i = 1; i < MAX_KEY_SIZE; i++) {
        if (max_value < frequency_values[i]) {
            max_value = frequency_values[i];
            max_index = i;
        }
    }

    return max_index;
}

void print_decrypt(const unsigned char* buff, size_t buff_size, const unsigned char* keys, int key_size) {
    int i, k;
    printf("Possible result:\n");
    for(i = 0, k = 0; i < buff_size; i++, k++) {
        printf("%c", buff[i] ^ keys[k % key_size]);
    }
    printf("\n");
}

int compute_key_length(const unsigned char *buff, size_t buff_size) {
    int i, k;
    double frequency_values[MAX_KEY_SIZE];
    
    memset(frequency_values, 0, sizeof(frequency_values));

    for (i = 1; i <= MAX_KEY_SIZE; i++) {
        unsigned int frequency_table[256];
        int bytes_in_set = 0;
   
        memset(frequency_table, 0,sizeof(frequency_table));

        for (k = 0; i * k < buff_size; k++, bytes_in_set++) {
            frequency_table[buff[i*k]]++;
        }
        
        double frequency_squared = 0.0;
        int value_check = 0;
        for(k = 0; k < 256; k++) {
            value_check += frequency_table[k];
            double frequency = frequency_table[k]/(double)bytes_in_set;
            frequency_squared += frequency * frequency;
        }

        if (value_check != bytes_in_set) {
            printf("Did not count all bytes.  Though there where %d, but only had %d\n", bytes_in_set, value_check);
        }
        frequency_values[i-1] = frequency_squared;
        printf("Key Size Frequency: %lf\n", frequency_squared);
    }

    return max_frequency(frequency_values) + 1;
}

typedef struct {
    double a_freq;
    double e_freq;
}canadites;

void find_key_values(unsigned char* buff, size_t buff_size, int key_size) {
    int i, n;
    unsigned int k;
    unsigned char plain_char;
    
    for (i = 0; i < key_size; i++) {
        canadites* canadate_list[256];

        memset(canadate_list, 0, sizeof(canadate_list));
        
        for (k = 0; k < 256; k++) {
            int e_count = 0;
            int a_count = 0;
            int byte_count = 0;
            bool valid = true;           
            for (n = 0; (n * key_size) + i < buff_size; n++, byte_count++) {
                plain_char = buff[(n*key_size)+i] ^ k;
                if (!valid_char(plain_char)) {
                    valid = false;
                    break;
                }
                if (plain_char == 'e') {
                    e_count++;    
                }
                else if(plain_char == 'a') {
                    a_count++;
                }
            }
            if (valid) {
                canadites * canadite = (canadites*) calloc(1, sizeof(canadites));
                canadite->e_freq = (double)e_count/(double)byte_count; 
                canadite->a_freq = (double)a_count/(double)byte_count; 
                canadate_list[k] = canadite; 
            }
        }
        
        for (k = 0; k < 256; k++) {
            if(canadate_list[k] != NULL) {
                printf("For Key index(%d) Canadate offset %02X for e freq %lf and a freq %lf\n",i, k,
                canadate_list[k]->e_freq, canadate_list[k]->a_freq);
                free(canadate_list[k]);
            }
        }
    }
}

int main(void) {
    unsigned char input[MAX_BUF];
    size_t buffer_size;
    unsigned char keys[7] = {0xAB, 0x0A, 0x80, 0xBB, 0x46, 0xDB, 0x2C};

    memset(input, 0, sizeof(input));
    buffer_size = loadBuffer(input);
  
    int key_size = compute_key_length(input, buffer_size);

    printf("Key Length: %d\n", key_size);
    
    find_key_values(input, buffer_size, key_size);

    print_decrypt(input, buffer_size, keys, 7);

    return 0;
}

