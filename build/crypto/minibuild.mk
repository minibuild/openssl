#include "../crypto_static/crypto.inc"

module_type = 'lib-shared'
module_name = 'crypto'

symbol_visibility_default = 1

prebuilt_lib_list_linux = ['dl','pthread']
prebuilt_lib_list_windows = ['crypt32', 'ws2_32', 'advapi32', 'user32']

lib_list = ['${@project_root}/zlib']

export_def_file = 'libcrypto.def'

export_winapi_only = [
  'RAND_event',
  'RAND_screen',
]

