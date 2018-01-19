include_dir_list = [
  '../../include',
  '../../vendor/include',
  '../../vendor',
]

src_search_dir_list = [
  '../../vendor/ssl',
  '../../vendor/ssl/record',
  '../../vendor/ssl/statem',
]

definitions_windows = ['WIN32_LEAN_AND_MEAN', '_UNICODE', 'UNICODE']

definitions = [
  'ECP_NISTZ256_ASM',
  'NDEBUG',
  'OPENSSLDIR="/usr/local/ssl"',
  'OPENSSL_API_COMPAT=0x10000000L',
  'OPENSSL_BN_ASM_MONT',
  'OPENSSL_NO_DYNAMIC_ENGINE',
  'OPENSSL_PIC',
  'OPENSSL_THREADS',
  'POLY1305_ASM',
  'SHA1_ASM',
  'SHA256_ASM',
  'SHA512_ASM',
  'ZLIB',
]

build_list = [
  'bio_ssl.c',
  'd1_lib.c',
  'd1_msg.c',
  'd1_srtp.c',
  'dtls1_bitmap.c',
  'methods.c',
  'pqueue.c',
  'rec_layer_d1.c',
  'rec_layer_s3.c',
  's3_cbc.c',
  's3_enc.c',
  's3_lib.c',
  's3_msg.c',
  'ssl3_buffer.c',
  'ssl3_record.c',
  'ssl_asn1.c',
  'ssl_cert.c',
  'ssl_ciph.c',
  'ssl_conf.c',
  'ssl_err.c',
  'ssl_init.c',
  'ssl_lib.c',
  'ssl_mcnf.c',
  'ssl_rsa.c',
  'ssl_sess.c',
  'ssl_stat.c',
  'ssl_txt.c',
  'ssl_utst.c',
  'statem.c',
  'statem_clnt.c',
  'statem_dtls.c',
  'statem_lib.c',
  'statem_srvr.c',
  't1_enc.c',
  't1_ext.c',
  't1_lib.c',
  't1_reneg.c',
  't1_trce.c',
  'tls_srp.c',
]

