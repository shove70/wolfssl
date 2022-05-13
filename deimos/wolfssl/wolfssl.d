module deimos.wolfssl.wolfssl;

public:

enum SSL_ERROR_NONE      =  0;   /* for most functions */
enum SSL_FAILURE         =  0;   /* for some functions */
enum SSL_SUCCESS         =  1;

enum SSL_SHUTDOWN_NOT_DONE = 2;  /* call wolfSSL_shutdown again to complete */

enum SSL_ALPN_NOT_FOUND  = -9;
enum SSL_BAD_CERTTYPE    = -8;
enum SSL_BAD_STAT        = -7;
enum SSL_BAD_PATH        = -6;
enum SSL_BAD_FILETYPE    = -5;
enum SSL_BAD_FILE        = -4;
enum SSL_NOT_IMPLEMENTED = -3;
enum SSL_UNKNOWN         = -2;
enum SSL_FATAL_ERROR     = -1;

enum SSL_FILETYPE_PEM     = 1;
enum SSL_FILETYPE_ASN1    = 2;
enum SSL_FILETYPE_DEFAULT = 2; /* ASN1 */
enum SSL_FILETYPE_RAW     = 3; /* NTRU raw key blob */

enum SSL_VERIFY_NONE                 = 0;
enum SSL_VERIFY_PEER                 = 1;
enum SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;
enum SSL_VERIFY_CLIENT_ONCE          = 4;
enum SSL_VERIFY_FAIL_EXCEPT_PSK      = 8;

enum SSL_SESS_CACHE_OFF                = 0x0000;
enum SSL_SESS_CACHE_CLIENT             = 0x0001;
enum SSL_SESS_CACHE_SERVER             = 0x0002;
enum SSL_SESS_CACHE_BOTH               = 0x0003;
enum SSL_SESS_CACHE_NO_AUTO_CLEAR      = 0x0008;
enum SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 0x0100;
enum SSL_SESS_CACHE_NO_INTERNAL_STORE  = 0x0200;
enum SSL_SESS_CACHE_NO_INTERNAL        = 0x0300;

enum SSL_ERROR_WANT_READ        =  2;
enum SSL_ERROR_WANT_WRITE       =  3;
enum SSL_ERROR_WANT_CONNECT     =  7;
enum SSL_ERROR_WANT_ACCEPT      =  8;
enum SSL_ERROR_SYSCALL          =  5;
enum SSL_ERROR_WANT_X509_LOOKUP =  83;
enum SSL_ERROR_ZERO_RETURN      =  6;
enum SSL_ERROR_SSL              =  85;

enum SSL_SENT_SHUTDOWN     = 1;
enum SSL_RECEIVED_SHUTDOWN = 2;
enum SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4;

enum SSL_R_SSL_HANDSHAKE_FAILURE           = 101;
enum SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102;
enum SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103;
enum SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104;

enum SSL_CBIO_ERR_GENERAL    = -1;     /* general unexpected err */
enum SSL_CBIO_ERR_WANT_READ  = -2;     /* need to call read  again */
enum SSL_CBIO_ERR_WANT_WRITE = -2;     /* need to call write again */
enum SSL_CBIO_ERR_CONN_RST   = -3;     /* connection reset */
enum SSL_CBIO_ERR_ISR        = -4;     /* interrupt */
enum SSL_CBIO_ERR_CONN_CLOSE = -5;     /* connection closed or epipe */
enum SSL_CBIO_ERR_TIMEOUT    = -6;     /* socket timeout */


alias SSL     = WOLFSSL;
alias SSL_CTX = WOLFSSL_CTX;

alias SSL_library_init                   = wolfSSL_library_init;
alias SSL_load_error_strings             = wolfSSL_load_error_strings;
alias ERR_print_errors_fp                = wolfSSL_ERR_dump_errors_fp;
alias ERR_free_strings                   = wolfSSL_ERR_free_strings;
alias OpenSSL_add_ssl_algorithms         = wolfSSL_add_all_algorithms;

alias TLS_server_method                  = wolfTLS_server_method;
alias TLS_client_method                  = wolfTLS_client_method;
alias TLSv1_server_method                = wolfTLSv1_server_method;
alias TLSv1_client_method                = wolfTLSv1_client_method;
alias TLSv1_1_server_method              = wolfTLSv1_1_server_method;
alias TLSv1_1_client_method              = wolfTLSv1_1_client_method;
alias TLSv1_2_server_method              = wolfTLSv1_2_server_method;
alias TLSv1_2_client_method              = wolfTLSv1_2_client_method;
alias TLSv1_3_server_method              = wolfTLSv1_3_server_method;
alias TLSv1_3_client_method              = wolfTLSv1_3_client_method;

alias SSL_CTX_new                        = wolfSSL_CTX_new;
alias SSL_CTX_load_verify_locations      = wolfSSL_CTX_load_verify_locations;
alias SSL_CTX_use_certificate_chain_file = wolfSSL_CTX_use_certificate_chain_file;
alias SSL_CTX_use_PrivateKey_file        = wolfSSL_CTX_use_PrivateKey_file;
alias SSL_CTX_check_private_key          = wolfSSL_CTX_check_private_key;
alias SSL_new                            = wolfSSL_new;
alias SSL_CTX_free                       = wolfSSL_CTX_free;
alias SSL_set_fd                         = wolfSSL_set_fd;
alias SSL_get_fd                         = wolfSSL_get_fd;
alias SSL_connect                        = wolfSSL_connect;
alias SSL_shutdown                       = wolfSSL_shutdown;
alias SSL_free                           = wolfSSL_free;
alias SSL_read                           = wolfSSL_read;
alias SSL_get_error                      = wolfSSL_get_error;
alias SSL_write                          = wolfSSL_write;
alias SSL_set_accept_state               = wolfSSL_set_accept_state;
alias SSL_SSL_do_handshake               = wolfSSL_SSL_do_handshake;
alias SSL_SSLSetIOSend                   = wolfSSL_SSLSetIOSend;
alias SSL_SSLSetIORecv                   = wolfSSL_SSLSetIORecv;

extern (C):

alias SSL_sendFunc                       = int function(WOLFSSL*, const void*, int, void*);
alias SSL_recvFunc                       = int function(WOLFSSL*, void*, int, void*);

struct FILE;
struct WOLFSSL_METHOD;
struct WOLFSSL_CTX;
struct WOLFSSL;

void  wolfSSL_library_init();
void  wolfSSL_load_error_strings();
void  wolfSSL_ERR_dump_errors_fp(FILE* fp);
void  wolfSSL_ERR_free_strings();
int   wolfSSL_add_all_algorithms();

WOLFSSL_METHOD* wolfTLS_server_method();
WOLFSSL_METHOD* wolfTLS_client_method();
WOLFSSL_METHOD* wolfTLSv1_server_method();
WOLFSSL_METHOD* wolfTLSv1_client_method();
WOLFSSL_METHOD* wolfTLSv1_1_server_method();
WOLFSSL_METHOD* wolfTLSv1_1_client_method();
WOLFSSL_METHOD* wolfTLSv1_2_server_method();
WOLFSSL_METHOD* wolfTLSv1_2_client_method();
WOLFSSL_METHOD* wolfTLSv1_3_server_method();
WOLFSSL_METHOD* wolfTLSv1_3_client_method();

WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD* method);
int          wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file, const char* path);
int          wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX* ctx, const char* file);
int          wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);
int          wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx);
WOLFSSL*     wolfSSL_new(WOLFSSL_CTX* ctx);
void         wolfSSL_CTX_free(WOLFSSL_CTX* ctx);
int          wolfSSL_set_fd(WOLFSSL* ssl, int fd);
int          wolfSSL_get_fd(WOLFSSL* ssl);
int          wolfSSL_connect(WOLFSSL* ssl);
int          wolfSSL_shutdown(WOLFSSL* ssl);
void         wolfSSL_free(WOLFSSL* ssl);
int          wolfSSL_read(WOLFSSL* ssl, void* data, int sz);
int          wolfSSL_get_error(WOLFSSL* ssl, int ret);
int          wolfSSL_write(WOLFSSL* ssl, const void* data, int sz);
void         wolfSSL_set_accept_state(WOLFSSL* ssl);
int          wolfSSL_SSL_do_handshake(WOLFSSL* ssl);
void         wolfSSL_SSLSetIOSend(WOLFSSL* ssl, SSL_sendFunc sendFunc);
void         wolfSSL_SSLSetIORecv(WOLFSSL* ssl, SSL_recvFunc recvFunc);
