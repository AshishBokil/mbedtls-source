#[allow(non_camel_case_types)]
pub struct mbedtls_cmac_context_t
{
    /** The internal state of the CMAC algorithm.  */
     pub  state:[u8;MBEDTLS_CIPHER_BLKSIZE_MAX],
    /** Unprocessed data - either data that was not block aligned and is still
     *  pending processing, or the final block. */

     pub unprocessed_block:[u8;MBEDTLS_CIPHER_BLKSIZE_MAX],
    /** The length of data pending processing. */
    
    pub  unprocessed_len:usize ,
}


//cmac_headers

pub const MBEDTLS_AES_BLOCK_SIZE  :usize=        16; /**< The longest block used by CMAC is that of AES. */
pub const MBEDTLS_DES3_BLOCK_SIZE :usize =       8;/**< The longest block used by CMAC is that of 3DES. */


pub const MBEDTLS_CIPHER_BLKSIZE_MAX:usize =     16;  /**< The longest block used by CMAC is that of AES. */

pub const NB_CMAC_TESTS_PER_KEY:usize= 4;
pub const NB_PRF_TESTS:usize= 3;



//cipher_headers

pub const MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE :i32 = -0x6080 ; /**< The selected feature is not available. */
pub const MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA  :i32 =     -0x6100 ; /**< Bad input parameters. */
pub const MBEDTLS_ERR_CIPHER_ALLOC_FAILED    :i32 =     -0x6180 ; /**< Failed to allocate memory. */
pub const MBEDTLS_ERR_CIPHER_INVALID_PADDING  :i32 =    -0x6200 ; /**< Input data contains invalid padding and is rejected. */
pub const MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED :i32 = -0x6280 ; /**< Decryption of block requires a full block. */
pub const MBEDTLS_ERR_CIPHER_AUTH_FAILED    :i32 =      -0x6300  ;/**< Authentication failed (for AEAD modes). */
pub const MBEDTLS_ERR_CIPHER_INVALID_CONTEXT :i32 =     -0x6380 ; /**< The context is invalid. For example, because it was freed. */

pub const MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED   :i32 =   -0x6400 ; /**< Cipher hardware accelerator failed. */

pub const MBEDTLS_CIPHER_VARIABLE_IV_LEN:i32 =     0x01;    /**< Cipher accepts IVs of variable length. */
pub const MBEDTLS_CIPHER_VARIABLE_KEY_LEN  :i32 =  0x02 ;   /**< Cipher accepts keys of variable length. */




//error.h file
//===========================================================================================================================================

pub const MBEDTLS_ERR_ERROR_GENERIC_ERROR       : i32 = -0x0001 ;  /**< Generic error */
pub const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : i32 = -0x006E ;  
