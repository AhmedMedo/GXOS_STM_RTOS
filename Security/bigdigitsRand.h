

/*	[v2.2] changed name from spRandom to bigdigitsRand */

#ifndef BIGDIGITSRAND_H_
#define BIGDIGITSRAND_H_ 1

#include "bigdigits.h"

#ifdef __cplusplus
extern "C" {
#endif

/**	Returns a "better" pseudo-random digit using internal RNG. */
DIGIT_T spBetterRand(void);

/** Generate a random mp number of bit length at most \c nbits using internal RNG 
@param[out] a to receive generated random number
@param[in]  ndigits number of digits in a
@param[in]  nbits maximum number of bits
@returns Number of digits actually set 
*/
size_t mpRandomBits(DIGIT_T a[], size_t ndigits, size_t nbits);

/* Added in [v2.4] */
/** Generate array of random octets (bytes) using internal RNG
 *  @remarks This function is in the correct form for BD_RANDFUNC to use in bdRandomSeeded(). 
  * \c seed is ignored. */
int mpRandomOctets(unsigned char *bytes, size_t nbytes, const unsigned char *seed, size_t seedlen);

#ifdef __cplusplus
}
#endif

#endif /* BIGDIGITSRAND_H_ */
