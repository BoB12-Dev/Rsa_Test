#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <string.h>

typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;


void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


BIGNUM* XEuclid(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b)
{
    // a가 0일 경우, x=0, y=1로 설정하고 최대공약수로 b를 반환
    if (BN_is_zero(a)) {
        BN_zero(x); // x = 0
        BN_one(y);  // y = 1
        return BN_dup(b); // b를 복제한 값을 gcd로 반환
    }

    // 임시 변수들을 생성
    BIGNUM* x1 = BN_new();
    BIGNUM* y1 = BN_new();
    BIGNUM* gcd = BN_new();

    // b를 a로 나눈 나머지를 구한다.
    BIGNUM* temp = BN_new();
    BN_mod(temp, b, a, BN_CTX_new());

    // 재귀적으로 XEuclid 함수를 호출하여 최대공약수(gcd)와 gcd의 계수 x1, y1을 계산한다.
    gcd = XEuclid(x1, y1, temp, a);

    // x = y1 - (b / a) * x1
    BN_div(temp, NULL, b, a, BN_CTX_new());
    BN_mul(temp, temp, x1, BN_CTX_new());
    BN_sub(x, y1, temp);

    // y = x1
    BN_copy(y, x1);

    // 메모리를 해제한다.
    BN_free(temp);
    BN_free(x1);
    BN_free(y1);

    return gcd;
}




//역원구하기 -> BN_mod_inverse대체
BIGNUM* mod_inverse(BIGNUM* x, BIGNUM* y, const BIGNUM* a, const BIGNUM* b)
{
    // a가 0일 경우, x=0, y=1로 설정하고 최대공약수로 b를 반환
    if (BN_is_zero(a)) {
        BN_zero(x); // x = 0
        BN_one(y);  // y = 1
        return BN_dup(b); // b를 복제한 값을 gcd로 반환
    }

    // 임시 변수들을 생성
    BIGNUM* x1 = BN_new();
    BIGNUM* y1 = BN_new();
    BIGNUM* gcd = BN_new();

    // b를 a로 나눈 나머지를 구한다.
    BIGNUM* temp = BN_new();
    BN_mod(temp, b, a, BN_CTX_new());

    // 재귀적으로 XEuclid 함수를 호출하여 최대공약수(gcd)와 gcd의 계수 x1, y1을 계산한다.
    gcd = XEuclid(x1, y1, temp, a);

    // x = y1 - (b / a) * x1
    BN_div(temp, NULL, b, a, BN_CTX_new());
    BN_mul(temp, temp, x1, BN_CTX_new());
    BN_sub(x, y1, temp);

    // y = x1
    BN_copy(y, y1);

    // 메모리를 해제한다.
    BN_free(temp);
    BN_free(x1);
    BN_free(y1);

    return y;
}


BIGNUM* calculate_d(const BIGNUM* e, const BIGNUM* phi)
{
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* result = BN_new();

    // e와 phi(N)에 대한 역원을 계산하여 x 값으로 저장
    mod_inverse(x, y, e, phi);

    // x가 음수일 경우 양수로 변환하여 최종 결과인 d 값을 계산
    if (BN_is_negative(x)) {
        BN_add(result, x, phi);
    } else {
        BN_copy(result, x);
    }

    // 메모리를 해제한다.
    BN_free(x);
    BN_free(y);

    return result;
}


int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    BIGNUM *result = BN_new();
    BIGNUM *base = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_one(result); // 초기값은 1로 설정

    int num_bits = BN_num_bits(e); // 지수 e의 비트 수

    // 지수 e의 이진 표현을 왼쪽에서 오른쪽으로 읽으면서 지수 연산 수행
    for (int i = num_bits - 1; i >= 0; i--)
    {
        BN_copy(base, result); // 이전 반복에서 계산된 결과를 base로 복사
        BN_mod_mul(result, base, base, m, ctx); // r = r^2 mod m
        if (BN_is_bit_set(e, i)) // e의 i번째 비트가 1인 경우
            BN_mod_mul(result, result, a, m, ctx); // r = r * a mod m
    }

    BN_copy(r, result); // 최종 결과를 r에 복사

    // 메모리 해제
    BN_free(result);
    BN_free(base);
    BN_CTX_free(ctx);

    return 1;
}


BOB12_RSA *BOB12_RSA_new() {
    BOB12_RSA *b12rsa = (BOB12_RSA *)malloc(sizeof(BOB12_RSA));
    if (b12rsa == NULL) {
        return NULL; // 메모리 할당 실패 시 NULL 반환
    }
    
    b12rsa->e = BN_new();
    b12rsa->d = BN_new();
    b12rsa->n = BN_new();
    
    return b12rsa;
} //구조체 메모리 할당


int BOB12_RSA_free(BOB12_RSA *b12rsa) {
    if (b12rsa == NULL) {
        return 0;
    }
    
    if (b12rsa->e != NULL) BN_free(b12rsa->e);
    if (b12rsa->d != NULL) BN_free(b12rsa->d);
    if (b12rsa->n != NULL) BN_free(b12rsa->n);
    
    free(b12rsa);
    
    return 1;
}

int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits) {
    // p와 q 값을 16진수 문자열에서 BIGNUM으로 변환
   
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_hex2bn(&p, "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7");
    BN_hex2bn(&q, "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F");
    
    // n = p * q
    BIGNUM *n = BN_new();
    BN_mul(n, p, q, ctx);

    
    BN_sub_word(p, 1);
    BN_sub_word(q, 1);

    //phi(n) = (p-1)*(q-1)
    BIGNUM *phi = BN_new();
    BN_mul(phi,p,q,ctx);
    
    
    // e, d 값 설정
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *tmp = BN_new();
    BN_dec2bn(&e, "65537"); // 일반적으로 작은 소수 사용
    mod_inverse(tmp, d, e, phi); // d 값을 계산하여 설정

    
    // 값 복사
    BN_copy(b12rsa->n, n);
    BN_copy(b12rsa->e, e);
    BN_copy(b12rsa->d, calculate_d(e, phi)); // d 값을 계산하여 설정);

    printBN("e = ", b12rsa->e);
    
    // 메모리 해제
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(phi);
    BN_free(e);
    BN_free(d);
    BN_CTX_free(ctx);
    
    return 1;
}



int BOB12_RSA_Enc(BIGNUM *c, const BIGNUM *m, const BOB12_RSA *b12rsa) {
    // 여기서 exp mod 사용
    // 암호문(C) = M^e mod N
    ExpMod(c, m, b12rsa->e, b12rsa->n);
}


int BOB12_RSA_Dec(BIGNUM *m, const BIGNUM *c, const BOB12_RSA *b12rsa) {
    // 여기서 exp mod 사용
    // 평문(M) = C^d mod N
    ExpMod(m, c, b12rsa->d, b12rsa->n);
}



void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa,1024);
        BN_print_fp(stdout,b12rsa->n);
        printf(" ");
        BN_print_fp(stdout,b12rsa->e);
        printf(" ");
        BN_print_fp(stdout,b12rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b12rsa->e, argv[2]);
            BOB12_RSA_Enc(out,in, b12rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b12rsa->d, argv[2]);
            BOB12_RSA_Dec(out,in, b12rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);

    return 0;
}
