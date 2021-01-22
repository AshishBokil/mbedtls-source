//use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use crate::cmac_header;

#[allow(non_camel_case_types)]
#[derive(PartialEq)]
pub enum  operation_t {
    MBEDTLS_OPERATION_NONE,     //: -1,
    MBEDTLS_DECRYPT,        //: 0,
    MBEDTLS_ENCRYPT,            //: 1,
}

#[allow(non_camel_case_types)]
pub struct cipher_context_t
{    /** Information about the associated cipher. */
    pub cipher_info: cipher_info_t,
    key_bitlen: i32,
    operation: operation_t,
    state:[u8;cmac_header::MBEDTLS_CIPHER_BLKSIZE_MAX ],
    cmac_ctx: &cmac_header::mbedtls_cmac_context_t ,
    add_padding: fn(),
    get_padding: fn(),
    unprocessed_data: [u32;16],
    unprocessed_len: usize,
    iv: [u8;16],
    iv_size: usize,
    psa_enabled: i32,
}

#[allow(non_camel_case_types)]
#[derive(EnumIter, Debug, PartialEq)]
pub enum cipher_type_t {

}

#[allow(non_camel_case_types)]
pub struct cipher_info_t
{
    pub cipher_type: cipher_type_t,
    key_bitlen: u32,
    name: String,
    iv_size: u32,
    flags: i32,
    pub block_size: usize,

}

pub fn mbedtls_cipher_init( ctx: cipher_context_t)
{
}

pub fn mbedtls_cipher_info_from_type(cipher_type: cipher_type_t ) ->Option<cipher_info_t>{
    return None;
}

pub fn mbedtls_cipher_setup(ctx: &mut cipher_context_t,
    cipher_info: cipher_info_t) -> i32{
        0
    }

pub fn cipher_update(ctx: &mut cipher_context_t, input: &[u8],
    ilen: &usize, output: &[u8], olen:&usize ) -> i32{
        0
    }

pub fn mbedtls_cipher_setkey(ctx:&cipher_context_t,
        key:&u8,
        key_bitlen:usize,
         operation:operation_t )->i32{

        0
        }

fn memcmp(){

}