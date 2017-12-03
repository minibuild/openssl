#include "../ssl_static/ssl.inc"

module_type = 'lib-shared'
module_name = 'ssl'

lib_list = ['../crypto']

symbol_visibility_default = 1

export_def_file = 'libssl.def'

