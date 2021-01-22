 //use crate::cmac_header;
 use  crate::cmac_header;
 use crate::cipher;
// #[path = "../enc_dec/cmac_header.rs"] mod cmac_header;
//use crate::cipher;
use std::mem;
use std::ptr;
use std::clone;
//use std::convert::TryFrom;
//use std::convert::TryInto;



pub fn cmac_multiply_by_u(output : &[u8],input : &[u8], block_size: usize)->i32{

    let R_128:u8 = 0x87;
    let R_64:u8 =0x1B;
    let mut R_n:u8;
    let mut mask:isize;
    let overflow:u8 = 0x00;
    let i:i32;
    if block_size == cmac_header::MBEDTLS_AES_BLOCK_SIZE 
    {
        R_n = R_128;
    }
    else if block_size  == cmac_header::MBEDTLS_DES3_BLOCK_SIZE {
    
        R_n = R_64;
    }
    else
    {
        return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
    }


    for i in (0..block_size).rev(){
        output[i] = input[i] << 1 | overflow;
        overflow = input[i] >> 7;
    }
    /* mask = ( input[0] >> 7 ) ? 0xff : 0x00
     * using bit operations to avoid branches */

     mask = - ( input[0] as isize  >> 7 );
     output[ block_size - 1 ] =output[ block_size - 1 ]  ^ (R_n as isize & mask)as u8;

    return 0 ;
}

pub fn mbedtls_platform_zeroize(L:&[u8],len:usize)
{
    let mut i:i32=0;
    while i<len as i32 {
        L[i as usize]=0;
        i=i+1;
    }
}

/*
 * Generate subkeys
 *
 * - as specified by RFC 4493, section 2.3 Subkey Generation Algorithm
 */
pub fn cmac_generate_subkeys(ctx: &mut cipher::cipher_context_t, K1 :&[u8] , K2 :&[u8])->i32{

    let mut ret:i32 =  cmac_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    let mut L:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX] ;
   // let mut L =vec![Default::default(); cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
    let ( olen, block_size):(&mut usize, usize);

    mbedtls_platform_zeroize(&L, mem::size_of::<[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX]>() );

    block_size = ctx.cipher_info.block_size ;

    /* Calculate Ek(0) */
    ret = cipher::cipher_update( ctx, &L, &block_size, &L, &mut olen );
    if ret != 0 {

        mbedtls_platform_zeroize( &L, mem::size_of::<[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX]>() );
    }
        

    /*
     * Generate K1 and K2
     */
    ret = cmac_multiply_by_u( K1, &L , block_size );
    if ret != 0 {
        mbedtls_platform_zeroize( &L, mem::size_of::<[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX]>() );
        return ret ;
    }
    ret = cmac_multiply_by_u( K2, K1 , block_size );
    if ret != 0 {
         mbedtls_platform_zeroize( &L, mem::size_of::<[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX]>() );
         return ret;
    }

    return ret;
}



pub fn cmac_xor_block(output : &[u8],input1 : &[u8],input2 : &[u8], block_size: usize){

    let mut idx:usize;

    for idx in 0..block_size{
        output[idx] =input1[idx] ^ input2[idx]; 
    }
}

/*
 * Create padded last block from (partial) last block.
 *
 * We can't use the padding option from the cipher layer, as it only works for
 * CBC and we use ECB mode, and anyway we need to XOR K1 or K2 in addition.
 */

pub fn cmac_pad(padded_block:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX],padded_block_len:usize,
                last_block: &[u8] , last_block_len :usize){

     let j:usize;

    for j in 0..padded_block_len{
        if j < last_block_len{
            padded_block[j] = last_block[j];
        } else if j == last_block_len {
            padded_block[j] = 0x80;
        } else {
            padded_block[j]= 0x00;
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
enum  operation_t {
    MBEDTLS_OPERATION_NONE,     //: -1,
    MBEDTLS_DECRYPT,        //: 0,
    MBEDTLS_ENCRYPT,            //: 1,
}

pub fn mbedtls_cipher_cmac_starts( ctx :&mut cipher::cipher_context_t,
    key: &u8,  keybits: usize )->i32{

        let  type_t:cipher::cipher_type_t;
        let  cmac_ctx: &cmac_header::mbedtls_cmac_context_t ;
        let mut retval:i32;

        retval= cipher::mbedtls_cipher_setkey( ctx, key, keybits,operation_t::MBEDTLS_ENCRYPT );
        if  retval != 0 {

            return retval;
        }

        type_t = ctx.cipher_info.cipher_type;
        let result =match type_t
        {
            MBEDTLS_CIPHER_AES_128_ECB => {},
             MBEDTLS_CIPHER_AES_192_ECB=>{} ,
             MBEDTLS_CIPHER_AES_256_ECB=>{} ,
             MBEDTLS_CIPHER_DES_EDE3_ECB=> {},
              _ =>  {return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;}   
               
        };
        
           
    
        ctx.cmac_ctx= cmac_ctx;
    
        mbedtls_platform_zeroize( cmac_ctx.state, mem::size_of::<cmac_ctx::state>()   );
    

        return 0;
 }


pub fn mbedtls_cipher_cmac_update(  ctx: &mut cipher::cipher_context_t,
    input : &u8, ilen : usize)->i32{
//

 let cmac_ctx:&cmac_header::mbedtls_cmac_context_t;
let state:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
let mut ret:i32 = 0;
let (mut n, mut j, mut olen , mut block_size) : (usize,usize,usize,usize);

if !ptr::eq(ctx.cmac_ctx, cmac_ctx) {

        return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
    }
    

cmac_ctx = ctx.cmac_ctx;
block_size = ctx::cipher_info::block_size;
state = ctx::cmac_ctx::state;

/* process data larger than block
 * size than a block? */
if cmac_ctx::unprocessed_len > 0 &&
    ilen > block_size - cmac_ctx::unprocessed_len{

    ptr::copy_nonoverlapping(input, &mut cmac_ctx::unprocessed_block[cmac_ctx::unprocessed_len], 
                                 block_size - cmac_ctx::unprocessed_len);

    cmac_xor_block( &state, cmac_ctx::unprocessed_block, &state, block_size );

    ret = cipher::cipher_update( ctx, &state, &block_size, &state,&olen );
    if ret != 0 
    {
      return ret;
    }

    input = &(input + block_size as u8 - cmac_ctx.unprocessed_len as u8);
    ilen -= block_size - cmac_ctx.unprocessed_len;
    cmac_ctx.unprocessed_len = 0;
}

/* n is the number of blocks including any final partial block */
n = ( ilen + block_size - 1 ) / block_size;

/* Iterate across the input data in block sized chunks, excluding any
 * final partial or complete block */
for j in 1..n{
    cmac_xor_block( &state, input, &state, block_size );

    ret = cipher::cipher_update( ctx, &state, &block_size, &state,&mut olen );
    if ret != 0 {

    return ret;
    }
      

    ilen -= block_size;
    input = &(input+block_size as u8);
}

/* If there is data left over that wasn't aligned to a block */
if ilen > 0 
{
 
    cmac_ctx::unprocessed_block[cmac_ctx::unprocessed_len]=input.clone();
    cmac_ctx::unprocessed_len += ilen;
}

return ret;
//
}

pub fn mbedtls_cipher_cmac_finish(ctx:&mut  cipher::cipher_context_t  ,
     output: &u8 )->i32{
//
let cmac_ctx:&mut cmac_header::mbedtls_cmac_context_t;
let state:[u8;1];
let last_block:[u8;1];
let  K1:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
let  K2:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
let mut M_last:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
let mut ret:i32 = cmac_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
let (mut olen,mut block_size):(usize,usize);

if  !ptr::eq(ctx,ctx)  {

        return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
    }
    

cmac_ctx = ctx.cmac_ctx;
block_size = ctx::cipher_info::block_size;
state = cmac_ctx::state;

mbedtls_platform_zeroize( &K1, mem::size_of::<K1>() );
mbedtls_platform_zeroize( &K2, mem::size_of::<K2>( ));
cmac_generate_subkeys( &ctx, &K1, &K2 );

last_block = cmac_ctx::unprocessed_block;

/* Calculate last block */
if cmac_ctx::unprocessed_len < block_size 
{
    cmac_pad( M_last, block_size, last_block, cmac_ctx::unprocessed_len );
    cmac_xor_block( &M_last, &M_last, &K2, block_size );
}
else
{
    /* Last block is complete block */
    cmac_xor_block( &M_last, &last_block, &K1, block_size );
}


cmac_xor_block( &state,& M_last, &state, block_size );

ret = cipher::cipher_update( ctx, &state, &block_size, &state,&olen );
if ret != 0 
{
    
mbedtls_platform_zeroize( &K1, mem::size_of::<K1>( ) );
mbedtls_platform_zeroize( &K2, mem::size_of::<K2>( ) );

cmac_ctx::unprocessed_len = 0;
mbedtls_platform_zeroize( cmac_ctx::unprocessed_block,
                          mem::size_of::<cmac_ctx::unprocessed_block>() );
mbedtls_platform_zeroize( &state, cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX );
return ret ;
}

///
memcpy( output, state, block_size );

/* Wipe the generated keys on the stack, and any other transients to avoid
 * side channel leakage */
mbedtls_platform_zeroize(&K1, mem::size_of::<K1>( ) );
mbedtls_platform_zeroize( &K2, mem::size_of::<K2>( ) );

cmac_ctx::unprocessed_len = 0;
mbedtls_platform_zeroize( cmac_ctx::unprocessed_block,
                          mem::size_of::< cmac_ctx::unprocessed_block>( ) );

mbedtls_platform_zeroize( &state, cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX );
return ret ;  


//
}

pub fn mbedtls_cipher_cmac_reset(ctx:&mut  cipher::cipher_context_t )->i32{
    let cmac_ctx:&mut cmac_header::mbedtls_cmac_context_t;

    if ctx.is_none() || ctx::cipher_info.is_none() || ctx::cmac_ctx.is_none {

        return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
    }
       

    cmac_ctx = ctx::cmac_ctx;

    /* Reset the internal state */
    cmac_ctx::unprocessed_len = 0;
    mbedtls_platform_zeroize( cmac_ctx::unprocessed_block,
                              mem::size_of::<cmac_ctx::unprocessed_block>() );
    mbedtls_platform_zeroize( cmac_ctx::state,
                              mem::size_of::<cmac_ctx::state>() );

    return 0 ;

}

pub fn mbedtls_cipher_cmac( cipher_info: &cipher::cipher_info_t,
key:&u8,  keylen: usize,
   input: &u8,  ilen : usize,
    output :&mut u8)->i32{
      
        let mut ctx:cipher::cipher_context_t;
        let mut ret:i32 = cmac_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    
        if cipher_info.is_none()  {
            return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
        }
           
    
        mbedtls_cipher_init( &mut ctx );
    
        ret = cipher::mbedtls_cipher_setup( &mut ctx, cipher_info );
        if ret != 0 {
            mem::drop( &mut ctx );
    
            return ret ;
        }
            
    
        ret = mbedtls_cipher_cmac_starts( &mut ctx, key, keylen );
        if ret != 0 {
            mem::drop( &mut ctx );
    
            return ret ;
        }
    
        ret = mbedtls_cipher_cmac_update( &mut ctx, input, ilen );
        if ret != 0 {
            mem::drop( &mut ctx );
    
            return ret ;
        }
        ret = mbedtls_cipher_cmac_finish( &mut ctx, output );
        mem::drop( &mut ctx );
    
        return ret ;

}
/*
pub fn mbedtls_aes_cmac_prf_128( key:&u8,  key_length :mut usize,
    input: &u8,  in_len :mut usize,
     output:mut [u8;16] )->i32{

         re:i32 = cmac_header::MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        const cipher_info:&cipher::cipher_info_t;
        let mut zero_key[u8;cmac_header::MBEDTLS_AES_BLOCK_SIZE];
        let mut int_key[u8;BEDTLS_AES_BLOCK_SIZE];
    
        if key.is_none() || input.is_none() || output.is_none() 
            return cmac_header::MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA ;
    
        cipher_info = cipher::mbedtls_cipher_info_from_type( cmac_header::MBEDTLS_CIPHER_AES_128_ECB );
        if( cipher_info.is_none() )
        {
            /* Failing at this point must be due to a build issue */
            ret = cmac_header::MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
            goto exit;
        }
    
        if( key_length == cmac_header::MBEDTLS_AES_BLOCK_SIZE )
        {
            /* Use key as is */
            memcpy( int_key, key, cmac_header::MBEDTLS_AES_BLOCK_SIZE );
        }
        else
        {
            memset( zero_key, 0, cmac_header::MBEDTLS_AES_BLOCK_SIZE );
    
            ret = mbedtls_cipher_cmac( cipher_info, zero_key, 128, key,
                                       key_length, int_key );
            if( ret != 0 )
                goto exit;
        }
    
        ret = mbedtls_cipher_cmac( cipher_info, int_key, 128, input, in_len,
                                   output );
    
    exit:
        mbedtls_platform_zeroize( int_key, mem::size_of::< in>(t_key ) );
    
        return( ret );

     }*/



/* All CMAC test inputs are truncated from the same 64 byte buffer. */
pub const test_mrssage:[u8;64 ]=[
    0x6b, 0xc1, 0xbe, 0xe2,     0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,     0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57,     0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac,     0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46,     0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19,     0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45,     0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b,     0xe6, 0x6c, 0x37, 0x10  
];

const aes_message_lengths:[u32;cmac_header::NB_CMAC_TESTS_PER_KEY]=[
   /* Mlen */
   0 ,
   16 ,
   20 ,
   64  
];


const aes_128_key:[u8;16]=[
    0x2b, 0x7e, 0x15, 0x16,     0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,     0x09, 0xcf, 0x4f, 0x3c
];


const aes_128_subkeys:[[u8;2];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* K1 */
        0xfb, 0xee, 0xd6, 0x18,     0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f,     0x72, 0x36, 0xa8, 0xde
    ],
    [
        /* K2 */
        0xf7, 0xdd, 0xac, 0x30,     0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e,     0xe4, 0x6d, 0x51, 0x3b
    ]
];
const aes_128_expected_result:[[u8;cmac_header::NB_CMAC_TESTS_PER_KEY];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* Example #1 */
        0xbb, 0x1d, 0x69, 0x29,     0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12,     0x9b, 0x75, 0x67, 0x46
    ],
    [
        /* Example #2 */
        0x07, 0x0a, 0x16, 0xb4,     0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d,     0xd0, 0x4a, 0x28, 0x7c
    ],
    [
        /* Example #3 */
        0x7d, 0x85, 0x44, 0x9e,     0xa6, 0xea, 0x19, 0xc8,
        0x23, 0xa7, 0xbf, 0x78,     0x83, 0x7d, 0xfa, 0xde
    ],
    [
        /* Example #4 */
        0x51, 0xf0, 0xbe, 0xbf,     0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17,     0x79, 0x36, 0x3c, 0xfe
    ]
];

/* CMAC-AES192 Test Data */
const aes_192_key:[u8;24] = [
    0x8e, 0x73, 0xb0, 0xf7,     0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b,     0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2,     0x52, 0x2c, 0x6b, 0x7b
];

const aes_192_subkeys:[[u8;2];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* K1 */
        0x44, 0x8a, 0x5b, 0x1c,     0x93, 0x51, 0x4b, 0x27,
        0x3e, 0xe6, 0x43, 0x9d,     0xd4, 0xda, 0xa2, 0x96
    ],
    [
        /* K2 */
        0x89, 0x14, 0xb6, 0x39,     0x26, 0xa2, 0x96, 0x4e,
        0x7d, 0xcc, 0x87, 0x3b,     0xa9, 0xb5, 0x45, 0x2c
    ]
];

const aes_192_expected_result:[[u8;cmac_header::NB_CMAC_TESTS_PER_KEY];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* Example #1 */
        0xd1, 0x7d, 0xdf, 0x46,     0xad, 0xaa, 0xcd, 0xe5,
        0x31, 0xca, 0xc4, 0x83,     0xde, 0x7a, 0x93, 0x67
    ],
    [
        /* Example #2 */
        0x9e, 0x99, 0xa7, 0xbf,     0x31, 0xe7, 0x10, 0x90,
        0x06, 0x62, 0xf6, 0x5e,     0x61, 0x7c, 0x51, 0x84
],
    [
        /* Example #3 */
        0x3d, 0x75, 0xc1, 0x94,     0xed, 0x96, 0x07, 0x04,
        0x44, 0xa9, 0xfa, 0x7e,     0xc7, 0x40, 0xec, 0xf8
],
    [
        /* Example #4 */
        0xa1, 0xd5, 0xdf, 0x0e,     0xed, 0x79, 0x0f, 0x79,
        0x4d, 0x77, 0x58, 0x96,     0x59, 0xf3, 0x9a, 0x11
]
];

/* CMAC-AES256 Test Data */
const aes_256_key:[u8;32] = [
    0x60, 0x3d, 0xeb, 0x10,     0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0,     0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07,     0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3,     0x09, 0x14, 0xdf, 0xf4
];
const aes_256_subkeys:[[u8;2];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* K1 */
        0xca, 0xd1, 0xed, 0x03,     0x29, 0x9e, 0xed, 0xac,
        0x2e, 0x9a, 0x99, 0x80,     0x86, 0x21, 0x50, 0x2f
    ],
    [
        /* K2 */
        0x95, 0xa3, 0xda, 0x06,     0x53, 0x3d, 0xdb, 0x58,
        0x5d, 0x35, 0x33, 0x01,     0x0c, 0x42, 0xa0, 0xd9
    ]
];
const aes_256_expected_result:[[u8;cmac_header::NB_CMAC_TESTS_PER_KEY];cmac_header::MBEDTLS_AES_BLOCK_SIZE] = [
    [
        /* Example #1 */
        0x02, 0x89, 0x62, 0xf6,     0x1b, 0x7b, 0xf8, 0x9e,
        0xfc, 0x6b, 0x55, 0x1f,     0x46, 0x67, 0xd9, 0x83
],
    [
        /* Example #2 */
        0x28, 0xa7, 0x02, 0x3f,     0x45, 0x2e, 0x8f, 0x82,
        0xbd, 0x4b, 0xf2, 0x8d,     0x8c, 0x37, 0xc3, 0x5c
],
    [
        /* Example #3 */
        0x15, 0x67, 0x27, 0xdc,     0x08, 0x78, 0x94, 0x4a,
        0x02, 0x3c, 0x1f, 0xe0,     0x3b, 0xad, 0x6d, 0x93
],
    [
        /* Example #4 */
        0xe1, 0x99, 0x21, 0x90,     0x54, 0x9f, 0x6e, 0xd5,
        0x69, 0x6a, 0x2c, 0x05,     0x6c, 0x31, 0x54, 0x10
]
];



/* Truncation point of message for 3DES CMAC tests  */
const des3_message_lengths:[u32;cmac_header::NB_CMAC_TESTS_PER_KEY] = [
    0,
    16,
    20,
    32
];

/* CMAC-TDES (Generation) - 2 Key Test Data */
const des3_2key_key:[u8;24] = [
    /* Key1 */
    0x01, 0x23, 0x45, 0x67,     0x89, 0xab, 0xcd, 0xef,
    /* Key2 */
    0x23, 0x45, 0x67, 0x89,     0xab, 0xcd, 0xEF, 0x01,
    /* Key3 */
    0x01, 0x23, 0x45, 0x67,     0x89, 0xab, 0xcd, 0xef
];
const des3_2key_subkeys:[[u8;2];8] = [
    [
        /* K1 */
        0x0d, 0xd2, 0xcb, 0x7a,     0x3d, 0x88, 0x88, 0xd9
    ],
    [
        /* K2 */
        0x1b, 0xa5, 0x96, 0xf4,     0x7b, 0x11, 0x11, 0xb2
    ]
];
const  des3_2key_expected_result:[[u8;cmac_header::NB_CMAC_TESTS_PER_KEY];cmac_header::MBEDTLS_DES3_BLOCK_SIZE] = [
    [
        /* Sample #1 */
        0x79, 0xce, 0x52, 0xa7,     0xf7, 0x86, 0xa9, 0x60
    ],
    [
        /* Sample #2 */
        0xcc, 0x18, 0xa0, 0xb7,     0x9a, 0xf2, 0x41, 0x3b
    ],
    [
        /* Sample #3 */
        0xc0, 0x6d, 0x37, 0x7e,     0xcd, 0x10, 0x19, 0x69
    ],
    [
        /* Sample #4 */
        0x9c, 0xd3, 0x35, 0x80,     0xf9, 0xb6, 0x4d, 0xfb
    ]
];

/* CMAC-TDES (Generation) - 3 Key Test Data */
const des3_3key_key:[u8;24] = [
    /* Key1 */
    0x01, 0x23, 0x45, 0x67,     0x89, 0xaa, 0xcd, 0xef,
    /* Key2 */
    0x23, 0x45, 0x67, 0x89,     0xab, 0xcd, 0xef, 0x01,
    /* Key3 */
    0x45, 0x67, 0x89, 0xab,     0xcd, 0xef, 0x01, 0x23
];

const  des3_3key_subkeys:[[u8;2];8] = [
    [
        /* K1 */
        0x9d, 0x74, 0xe7, 0x39,     0x33, 0x17, 0x96, 0xc0
],
    [
        /* K2 */
        0x3a, 0xe9, 0xce, 0x72,     0x66, 0x2f, 0x2d, 0x9b
]
];
 const  des3_3key_expected_result:[[u8;cmac_header::NB_CMAC_TESTS_PER_KEY];cmac_header::MBEDTLS_DES3_BLOCK_SIZE] = [
    [
        /* Sample #1 */
        0x7d, 0xb0, 0xd3, 0x7d,     0xf9, 0x36, 0xc5, 0x50
    ],
    [
        /* Sample #2 */
        0x30, 0x23, 0x9c, 0xf1,     0xf5, 0x2e, 0x66, 0x09
    ],
    [
        /* Sample #3 */
        0x6c, 0x9f, 0x3e, 0xe4,     0x92, 0x3f, 0x6b, 0xe2
    ],
    [
        /* Sample #4 */
        0x99, 0x42, 0x9b, 0xd0,     0xbF, 0x79, 0x04, 0xe5
    ]
 ];



/* AES AES-CMAC-PRF-128 Test Data */
 const  PRFK:[u8;18] = [
    /* Key */
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,     0x0c, 0x0d, 0x0e, 0x0f,
    0xed, 0xcb
 ];

/* Sizes in bytes */
 const  PRFKlen:[usize;cmac_header::NB_PRF_TESTS] = [
    18,
    16,
    10
 ];

/* Message */
 const  PRFM:[u8;20] = [
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,     0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
 ];

 const  PRFT:[[u8;cmac_header::NB_PRF_TESTS];16] = [
    [
        0x84, 0xa3, 0x48, 0xa4,     0xa4, 0x5d, 0x23, 0x5b,
        0xab, 0xff, 0xfc, 0x0d,     0x2b, 0x4d, 0xa0, 0x9a
    ],
    [
        0x98, 0x0a, 0xe8, 0x7b,     0x5f, 0x4c, 0x9c, 0x52,
        0x14, 0xf5, 0xb6, 0xa8,     0x45, 0x5e, 0x4c, 0x2d
    ],
    [
        0x29, 0x0d, 0x9e, 0x11,     0x2e, 0xdb, 0x09, 0xee,
        0x14, 0x1f, 0xcf, 0x64,     0xc0, 0xb7, 0x2f, 0x3d
    ]
 ];



 pub fn cmac_test_subkeys(  verbose:i32,
     testname:&u8,
     key:&u8,
   keybits: usize,
   subkeys :&u8,
   cipher_type :cipher::cipher_type_t,
     block_size : i32,
    num_tests: i32 )->i32{

       let (mut i,mut ret):(i32,i32);
     let mut  ret=0;
    let mut ctx:cipher::cipher_context_t;
    let cipher_info:cipher::cipher_info_t;
    let mut K1:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
    let mut K2:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];

   

    for i in 0..num_tests 
    {
        if verbose != 0{

            println!( "  {} CMAC subkey #{}: ", testname, i + 1 );
        } 
            

        cipher::mbedtls_cipher_init( ctx );

        ret = cipher::mbedtls_cipher_setup( &mut ctx, cipher_info );
        if ret != 0  {
            if verbose != 0 {

                println!( "test execution failed\n" );
                mbedtls_platform_zeroize( ctx::cmac_ctx,
                    mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
                    mem::drop( ctx::cmac_ctx );
                    return ret;
            }
               
           
        }

        if ( ret = cipher::mbedtls_cipher_setkey( &ctx, key, keybits,
                                       cipher::operation_t::MBEDTLS_ENCRYPT ) ) != 0 
        {
            if verbose != 0 {

                println!( "test execution failed\n" );
            }
                

              mbedtls_platform_zeroize( ctx::cmac_ctx,
                                                mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
              mem::drop( ctx::cmac_ctx );
                 return ret;
        }

        ret = cmac_generate_subkeys( &mut ctx, &K1, &K2 );
        if ret != 0 
            {
           if verbose != 0 {

            println!( "failed\n" );
           }
                
   
               mbedtls_platform_zeroize( ctx::cmac_ctx,
                                                mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
              mem::drop( ctx::cmac_ctx );
                 return ret;
        }
        ret = memcmp( K1, subkeys, block_size );
        if ret !=0{
            if verbose != 0 {

                println!( "failed\n" );
            }
           

            mbedtls_platform_zeroize( ctx::cmac_ctx,
                mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
                mem::drop( ctx::cmac_ctx );
                return ret; 
        }
        ret = memcmp( K2, subkeys, block_size );
        if ret != 0  
        {
            if verbose != 0 {

                println!( "failed\n" );
            }
           

            mbedtls_platform_zeroize( ctx::cmac_ctx,
                mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
                mem::drop( ctx::cmac_ctx );
                return ret;
        }

        if verbose != 0 {
            println!( "passed\n" );

        }
            
            mbedtls_platform_zeroize( ctx::cmac_ctx,
                mem::size_of::< cmac_header::mbedtls_cmac_context_t>() );
            mem::drop( ctx::cmac_ctx );
            return ret;
    }

    ret = 0;
    return ret;

 }

 

pub fn cmac_test_wth_cipher( verbose:i32,
         testname :&u8,
         key:&u8,
         keybits:i32,
        messages :&u8,
        message_lengths:[u32;4],
         expected_result:&u8,
         cipher_type : cipher::cipher_type_t ,
         block_size:  i32,
         num_tests : i32)->i32{


            let cipher_info:&cipher::cipher_info_t;
            let mut i:i32;
            let mut ret:i32=0;
            let mut output:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX];
        
            cipher_info = cipher::mbedtls_cipher_info_from_type( cipher_type );
            if cipher_info.is_none() 
            {
                /* Failing at this point must be due to a build issue */
                ret = cmac_header::MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
                return ret ;
            }
        
            for i in  0..num_tests
            {
                if verbose != 0 {

                    println!( "  {} CMAC #{}: ", testname, i + 1 );
                }
                    
        
                if ( ret = mbedtls_cipher_cmac( cipher_info, key, keybits, messages,
                                                 message_lengths[i], output ) ) != 0 
                {
                    if verbose != 0 {

                        println!( "failed\n" );
                        return ret ;
                    }
                        
                }
        
                if ( ret = memcmp( output, &expected_result[i * block_size], block_size ) ) != 0 
                {
                    if verbose != 0 {

                        println!( "failed\n" );
                        return ret ;
                    }
                }
        
                if verbose != 0 {

                    println!( "passed\n" );
                }
                    
            }
            ret = 0;
            return ret ;

}


