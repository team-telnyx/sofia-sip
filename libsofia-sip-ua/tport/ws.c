#include <switch.h>
#include "ws.h"
#include <pthread.h>

#ifndef _MSC_VER
#include <fcntl.h>
#endif

#if defined(__linux__) || defined(__GLIBC__)
#include <byteswap.h>
#endif

#ifndef _MSC_VER
#define ms_sleep(x)	usleep( x * 1000);
#else
#define ms_sleep(x) Sleep( x );
#endif

#ifdef _MSC_VER
/* warning C4706: assignment within conditional expression*/
#pragma warning(disable: 4706)
#endif

#define WS_BLOCK 10000	/* ms, blocks read operation for 10 seconds */
#define WS_SOFT_BLOCK 1000 /* ms, blocks read operation for 1 second */
#define WS_NOBLOCK 0

#define WS_INIT_SANITY 5000
#define WS_WRITE_SANITY 200

#define SHA1_HASH_SIZE 20
static struct ws_globals_s ws_globals;
ssize_t ws_global_payload_size_max = 0;

#ifndef WSS_STANDALONE

#define snprintf_nowarn(...) (snprintf(__VA_ARGS__) < 0 ? printf("snprintf failure") : (void)0)

void init_ssl(void)
{
	//	SSL_library_init();
	SSL_load_error_strings();
}
void deinit_ssl(void)
{
	return;
}

#else
static void pthreads_thread_id(CRYPTO_THREADID *id);
static void pthreads_locking_callback(int mode, int type, const char *file, int line);

static pthread_mutex_t *lock_cs;
static long *lock_count;



static void thread_setup(void)
{
	int i;

	lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

	for (i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(lock_cs[i]), NULL);
	}

	CRYPTO_THREADID_set_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

static void thread_cleanup(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);

	for (i=0; i<CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(lock_cs[i]));
	}
	OPENSSL_free(lock_cs);
	OPENSSL_free(lock_count);

}

static void pthreads_locking_callback(int mode, int type, const char *file, int line)
{

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(lock_cs[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(lock_cs[type]));
	}
}



static void pthreads_thread_id(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}


void init_ssl(void) {
	SSL_library_init();


	OpenSSL_add_all_algorithms();   /* load & register cryptos */
	SSL_load_error_strings();     /* load all error messages */
	ws_globals.ssl_method = SSLv23_server_method();   /* create server instance */
	ws_globals.ssl_ctx = SSL_CTX_new(ws_globals.ssl_method);         /* create context */
	assert(ws_globals.ssl_ctx);

	/* Disable SSLv2 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_SSLv2);
	/* Disable SSLv3 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_SSLv3);
	/* Disable TLSv1 */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_TLSv1);
	/* Disable Compression CRIME (Compression Ratio Info-leak Made Easy) */
	SSL_CTX_set_options(ws_globals.ssl_ctx, SSL_OP_NO_COMPRESSION);
	/* set the local certificate from CertFile */
	SSL_CTX_use_certificate_file(ws_globals.ssl_ctx, ws_globals.cert, SSL_FILETYPE_PEM);
	/* set the private key from KeyFile */
	SSL_CTX_use_PrivateKey_file(ws_globals.ssl_ctx, ws_globals.key, SSL_FILETYPE_PEM);
	/* verify private key */
	if ( !SSL_CTX_check_private_key(ws_globals.ssl_ctx) ) {
		abort();
    }

	SSL_CTX_set_cipher_list(ws_globals.ssl_ctx, "HIGH:!DSS:!aNULL@STRENGTH");

	thread_setup();
}


void deinit_ssl(void) {
	thread_cleanup();
}

#endif

static const char c64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


static int cheezy_get_var(char *data, char *name, char *buf, size_t buflen)
{
  char *p=data;

  /* the old way didnt make sure that variable values were used for the name hunt
   * and didnt ensure that only a full match of the variable name was used
   */

  do {
    if(!strncasecmp(p,name,strlen(name)) && *(p+strlen(name))==':') break;
  } while((p = (strstr(p,"\n")+1))!=(char *)1);


  if (p && p != (char *)1 && *p!='\0') {
    char *v, *e = 0;

    v = strchr(p, ':');
    if (v) {
      v++;
      while(v && *v == ' ') {
	v++;
      }
      if (v)  {
	e = strchr(v, '\r');
	if (!e) {
	  e = strchr(v, '\n');
	}
      }

      if (v && e) {
	int cplen;
	size_t len = e - v;

	if (len > buflen - 1) {
	  cplen = buflen -1;
	} else {
	  cplen = len;
	}

	strncpy(buf, v, cplen);
	*(buf+cplen) = '\0';
	return 1;
      }

    }
  }
  return 0;
}

static int b64encode(unsigned char *in, size_t ilen, unsigned char *out, size_t olen)
{
	int y=0,bytes=0;
	size_t x=0;
	unsigned int b=0,l=0;

	if(olen) {
	}

	for(x=0;x<ilen;x++) {
		b = (b<<8) + in[x];
		l += 8;
		while (l >= 6) {
			out[bytes++] = c64[(b>>(l-=6))%64];
			if(++y!=72) {
				continue;
			}
			//out[bytes++] = '\n';
			y=0;
		}
	}

	if (l > 0) {
		out[bytes++] = c64[((b%16)<<(6-l))%64];
	}
	if (l != 0) while (l < 6) {
		out[bytes++] = '=', l += 2;
	}

	return 0;
}

#ifdef NO_OPENSSL
static void sha1_digest(char *digest, unsigned char *in)
{
	SHA1Context sha;
	char *p;
	int x;


	SHA1Init(&sha);
	SHA1Update(&sha, in, strlen(in));
	SHA1Final(&sha, digest);
}
#else

static void sha1_digest(unsigned char *digest, char *in)
{
	SHA_CTX sha;

	SHA1_Init(&sha);
	SHA1_Update(&sha, in, strlen(in));
	SHA1_Final(digest, &sha);

}

#endif

int ws_handshake(wsh_t *wsh)
{
	char key[256] = "";
	char version[5] = "";
	char proto[256] = "";
	char proto_buf[384] = "";
	char input[512] = "";
	unsigned char output[SHA1_HASH_SIZE] = "";
	char b64[256] = "";
	char respond[1024] = "";
	ssize_t bytes;
	char *p, *e = 0;

	if (wsh->sock == ws_sock_invalid) {
		return -3;
	}

	while((bytes = ws_raw_read(wsh, wsh->buffer + wsh->datalen, wsh->buflen - wsh->datalen, WS_NOBLOCK)) > 0) {
		wsh->datalen += bytes;
		if (strstr(wsh->buffer, "\r\n\r\n") || strstr(wsh->buffer, "\n\n")) {
			break;
		}
	}

	if (bytes < 0 || bytes > wsh->buflen -1) {
		goto err;
	}

	*(wsh->buffer + wsh->datalen) = '\0';

	if (strncasecmp(wsh->buffer, "GET ", 4)) {
		goto err;
	}

	p = wsh->buffer + 4;

	e = strchr(p, ' ');
	if (!e) {
		goto err;
	}

	wsh->uri = malloc((e-p) + 1);

	if (!wsh->uri) goto err;

	strncpy(wsh->uri, p, e-p);
	*(wsh->uri + (e-p)) = '\0';

	cheezy_get_var(wsh->buffer, "Sec-WebSocket-Key", key, sizeof(key));
	cheezy_get_var(wsh->buffer, "Sec-WebSocket-Version", version, sizeof(version));
	cheezy_get_var(wsh->buffer, "Sec-WebSocket-Protocol", proto, sizeof(proto));

	if (!*key) {
		goto err;
	}

	snprintf(input, sizeof(input), "%s%s", key, WEBSOCKET_GUID);
	sha1_digest(output, input);
	b64encode((unsigned char *)output, SHA1_HASH_SIZE, (unsigned char *)b64, sizeof(b64));

	if (*proto) {
		snprintf(proto_buf, sizeof(proto_buf), "Sec-WebSocket-Protocol: %s\r\n", proto);
	}

	snprintf(respond, sizeof(respond),
			 "HTTP/1.1 101 Switching Protocols\r\n"
			 "Upgrade: websocket\r\n"
			 "Connection: Upgrade\r\n"
			 "Sec-WebSocket-Accept: %s\r\n"
			 "%s\r\n",
			 b64,
			 proto_buf);
	respond[511] = 0;

	if (ws_raw_write(wsh, respond, strlen(respond)) != (ssize_t)strlen(respond)) {
		goto err;
	}

	wsh->handshake = 1;

	return 0;

 err:

	if (!wsh->stay_open) {

		if (bytes > 0) {
			snprintf(respond, sizeof(respond), "HTTP/1.1 400 Bad Request\r\n"
					 "Sec-WebSocket-Version: 13\r\n\r\n");
			respond[511] = 0;

			ws_raw_write(wsh, respond, strlen(respond));
		}

		if (bytes == -2) {
			return 0;
		}

		ws_close(wsh, WS_NONE);
	}

	return -1;

}

#define SSL_IO_ERROR(err) (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL)
#define SSL_WANT_READ_WRITE(err) (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
int wss_error(wsh_t *wsh, int ssl_err, char const *who);

ssize_t ws_raw_read(wsh_t *wsh, void *data, size_t bytes, int block)
{
	ssize_t r;
	int ssl_err = 0;
	int block_n = block / 10;

	wsh->x++;
	if (wsh->x > 250) ms_sleep(1);

	if (wsh->ssl) {
		do {
			//ERR_clear_error();
			r = SSL_read(wsh->ssl, data, bytes);

			if (r <= 0) {
				ssl_err = SSL_get_error(wsh->ssl, r);

				if (SSL_WANT_READ_WRITE(ssl_err)) {
					if (!block) {
						r = -2;
						goto end;
					}
					wsh->x++;
					ms_sleep(10);
				} else {
					wss_error(wsh, ssl_err, "ws_raw_read: SSL_read");
					if (SSL_IO_ERROR(ssl_err)) {
						wsh->ssl_io_error = 1;
					}

					r = -1;
					goto end;
				}
			}

		} while (r < 0 && SSL_WANT_READ_WRITE(ssl_err) && wsh->x < block_n);

		goto end;
	}

	do {

		r = recv(wsh->sock, data, bytes, 0);

		if (r == -1) {
			if (!block && xp_is_blocking(xp_errno())) {
				r = -2;
				goto end;
			}

			if (block) {
				wsh->x++;
				ms_sleep(10);
			}
		}
	} while (r == -1 && xp_is_blocking(xp_errno()) && wsh->x < block_n);

 end:

	if (wsh->x >= 10000 || (block && wsh->x >= block_n)) {
		r = -1;
	}

	if (r > 0) {
		*((char *)data + r) = '\0';
	}

	if (r >= 0) {
		wsh->x = 0;
	}

	return r;
}

/** Log WSS error(s).
 *
 * Log the WSS error specified by the error code @a e and all the errors in
 * the queue. The error code @a e implies no error, and it is not logged.
 */
void wss_log_errors(unsigned level, char const *s, unsigned long e)
{
	if (e == 0)
		e = ERR_get_error();

	if (!tport_log->log_init)
		su_log_init(tport_log);

	if (s == NULL) s = "tls";

	for (; e != 0; e = ERR_get_error()) {
		if (level <= tport_log->log_level) {
			const char *error = ERR_lib_error_string(e);
			const char *func = ERR_func_error_string(e);
			const char *reason = ERR_reason_error_string(e);

			su_llog(tport_log, level, "%s: %08lx:%s:%s:%s\n",
				s, e, error, func, reason);
		}
	}
}

int wss_error(wsh_t *wsh, int ssl_err, char const *who)
{
	switch (ssl_err) {
	case SSL_ERROR_ZERO_RETURN:
		return 0;

	case SSL_ERROR_SYSCALL:
		ERR_clear_error();
		if (SSL_get_shutdown(wsh->ssl) & SSL_RECEIVED_SHUTDOWN)
			return 0;			/* EOS */
		if (errno == 0)
			return 0;			/* EOS */

		errno = EIO;
		return -1;

	default:
		wss_log_errors(1, who, ssl_err);
		errno = EIO;
		return -1;
	}
}

/*
 * Blocking read until bytes have been received, failure, or too many retries.
 */
static ssize_t ws_raw_read_blocking(wsh_t *wsh, char *data, size_t max_bytes, int max_retries)
{
	ssize_t total_bytes_read = 0;
	while (total_bytes_read < max_bytes && max_retries-- > 0) {
		ssize_t bytes_read = ws_raw_read(wsh, data + total_bytes_read, max_bytes - total_bytes_read, WS_BLOCK);
		if (bytes_read < 0) {
			break;
		}
		total_bytes_read += bytes_read;
	}
	return total_bytes_read;
}

ssize_t ws_raw_write(wsh_t *wsh, void *data, size_t bytes)
{
	ssize_t r;
	int sanity = WS_WRITE_SANITY;
	int ssl_err = 0;
	size_t wrote = 0;

	if (wsh == NULL || data == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (wsh->ssl) {
		do {
			void *buf = (void *)((unsigned char *)data + wrote);
			int size = bytes - wrote;

			//ERR_clear_error();
			r = SSL_write(wsh->ssl, buf, size);

			if (r == 0) {
				ssl_err = SSL_get_error(wsh->ssl, r);
				if (SSL_IO_ERROR(ssl_err)) {
					wsh->ssl_io_error = 1;
				}

				ssl_err = -42;
				break;
			}
			
			if (r > 0) {
				wrote += r;
			}

			if (sanity < WS_WRITE_SANITY) {
				int ms = 1;

				if (wsh->block) {
					if (sanity < WS_WRITE_SANITY / 2) {
						ms = 25;
					} else if (sanity < WS_WRITE_SANITY * 3 / 4) {
						ms = 50;
					}
				}

				ms_sleep(ms);
			}

			if (r < 0) {
				ssl_err = SSL_get_error(wsh->ssl, r);

				if (!SSL_WANT_READ_WRITE(ssl_err)) {
					if (SSL_IO_ERROR(ssl_err)) {
						wsh->ssl_io_error = 1;
					}

					ssl_err = wss_error(wsh, ssl_err, "ws_raw_write: SSL_write");
					break;
				}

				ssl_err = 0;
			}

		} while (--sanity > 0 && wrote < bytes);

		if (!sanity) ssl_err = -56;
		
		if (ssl_err) {
			r = ssl_err;
		}

		return r < 0 ? r : wrote;
	}

	do {
		r = send(wsh->sock, (void *)((unsigned char *)data + wrote), bytes - wrote, 0);

		if (r > 0) {
			wrote += r;
		}

		if (sanity < WS_WRITE_SANITY) {
			int ms = 1;

			if (wsh->block) {
				if (sanity < WS_WRITE_SANITY / 2) {
					ms = 25;
				} else if (sanity < WS_WRITE_SANITY * 3 / 4) {
					ms = 50;
				}
			}
			ms_sleep(ms);
		}

		if (r == -1) {
			if (!xp_is_blocking(xp_errno())) {
				break;
			}
		}

	} while (--sanity > 0 && wrote < bytes);

	//if (r<0) {
		//printf("wRITE FAIL: %s\n", strerror(errno));
	//}

	return r < 0 ? r : wrote;
}

#ifdef _MSC_VER
static int setup_socket(ws_socket_t sock)
{
	unsigned long v = 1;

	if (ioctlsocket(sock, FIONBIO, &v) == SOCKET_ERROR) {
		return -1;
	}

	return 0;

}

#else

static int setup_socket(ws_socket_t sock)
{
	int flags = fcntl(sock, F_GETFL, 0);
	return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

#endif


int establish_logical_layer(wsh_t *wsh)
{

	if (!wsh->sanity) {
		return -1;
	}

	if (wsh->logical_established) {
		return 0;
	}

	if (wsh->secure && !wsh->secure_established) {
		int code;

		if (!wsh->ssl) {
			wsh->ssl = SSL_new(wsh->ssl_ctx);
			assert(wsh->ssl);

			SSL_set_fd(wsh->ssl, wsh->sock);
		}

		do {
			code = SSL_accept(wsh->ssl);

			if (code == 1) {
				wsh->secure_established = 1;
				break;
			}

			if (code == 0) {
				return -1;
			}

			if (code < 0) {
				int ssl_err = SSL_get_error(wsh->ssl, code);
				if (!SSL_WANT_READ_WRITE(ssl_err)) {
					wss_error(wsh, ssl_err, "establish_logical_layer: SSL_accept");
					return -1;
				}
			}

			if (wsh->block) {
				ms_sleep(10);
			} else {
				ms_sleep(1);
			}

			wsh->sanity--;

			if (!wsh->block) {
				return -2;
			}

		} while (wsh->sanity > 0);

		if (!wsh->sanity) {
			return -1;
		}

	}

	while (!wsh->down && !wsh->handshake) {
		int r = ws_handshake(wsh);

		if (r < 0) {
			wsh->down = 1;
			return -1;
		}

		if (!wsh->handshake && !wsh->block) {
			return -2;
		}

	}

	wsh->logical_established = 1;

	return 0;
}

void ws_set_global_payload_size_max(ssize_t bytes)
{
	ws_global_payload_size_max = bytes;
}

int ws_init(wsh_t *wsh, ws_socket_t sock, SSL_CTX *ssl_ctx, int close_sock, int block, int stay_open)
{
	memset(wsh, 0, sizeof(*wsh));

	wsh->payload_size_max = ws_global_payload_size_max;
	wsh->sock = sock;
	wsh->block = block;
	wsh->sanity = WS_INIT_SANITY;
	wsh->ssl_ctx = ssl_ctx;
	wsh->stay_open = stay_open;

	if (!ssl_ctx) {
		ssl_ctx = ws_globals.ssl_ctx;
	}

	if (close_sock) {
		wsh->close_sock = 1;
	}

	wsh->buflen = 1024 * 64;
	wsh->bbuflen = wsh->buflen;

	wsh->buffer = malloc(wsh->buflen);
	wsh->bbuffer = malloc(wsh->bbuflen);
	//printf("init %p %ld\n", (void *) wsh->bbuffer, wsh->bbuflen);
	//memset(wsh->buffer, 0, wsh->buflen);
	//memset(wsh->bbuffer, 0, wsh->bbuflen);

	wsh->secure = ssl_ctx ? 1 : 0;

	setup_socket(sock);

	if (establish_logical_layer(wsh) == -1) {
		return -1;
	}

	if (wsh->down) {
		return -1;
	}

	return 0;
}

void ws_destroy(wsh_t *wsh)
{

	if (!wsh) {
		return;
	}

	if (!wsh->down) {
		ws_close(wsh, WS_NONE);
	}

	if (wsh->down > 1) {
		return;
	}

	wsh->down = 2;

	if (wsh->write_buffer) {
		free(wsh->write_buffer);
		wsh->write_buffer = NULL;
		wsh->write_buffer_len = 0;
	}

	if (wsh->buffer) free(wsh->buffer);
	if (wsh->bbuffer) free(wsh->bbuffer);

	wsh->buffer = wsh->bbuffer = NULL;

}

ssize_t ws_close(wsh_t *wsh, int16_t reason)
{

	if (wsh->down) {
		return -1;
	}

	wsh->down = 1;

	if (wsh->uri) {
		free(wsh->uri);
		wsh->uri = NULL;
	}

	if (reason && wsh->sock != ws_sock_invalid) {
		uint16_t *u16;
		uint8_t fr[4] = {WSOC_CLOSE | 0x80, 2, 0};

		u16 = (uint16_t *) &fr[2];
		*u16 = htons((int16_t)reason);
		ws_raw_write(wsh, fr, 4);
	}

	if (wsh->ssl) {
		int code = 0, rcode = 0;
		int ssl_error = 0;
		int n = 0, block_n = WS_SOFT_BLOCK / 10;

		/* SSL layer was never established or underlying IO error occured */
		if (!wsh->secure_established || wsh->ssl_io_error) {
			goto ssl_finish_it;
		}

		/* connection has been already closed */
		if (SSL_get_shutdown(wsh->ssl) & SSL_SENT_SHUTDOWN) {
				goto ssl_finish_it;
		}

		/* peer closes the connection */
		if (SSL_get_shutdown(wsh->ssl) & SSL_RECEIVED_SHUTDOWN) {
			SSL_shutdown(wsh->ssl);
			goto ssl_finish_it;
		}

		/* us closes the connection. We do bidirection shutdown handshake */
		for(;;) {
			code = SSL_shutdown(wsh->ssl);
			ssl_error = SSL_get_error(wsh->ssl, code);
			if (code <= 0 && ssl_error == SSL_ERROR_WANT_READ) {
				/* need to make sure there are no more data to read */
				for(;;) {
					if ((rcode = SSL_read(wsh->ssl, wsh->buffer, 9)) <= 0) {
						ssl_error = SSL_get_error(wsh->ssl, rcode);
						if (ssl_error == SSL_ERROR_ZERO_RETURN) {
							break;
						} else if (SSL_IO_ERROR(ssl_error)) {
							goto ssl_finish_it;
						} else if (ssl_error == SSL_ERROR_WANT_READ) {
							if (++n == block_n) {
								goto ssl_finish_it;
							}

							ms_sleep(10);
						} else {
							goto ssl_finish_it;
						}
					}
				}
			} else if (code == 0 || (code < 0 && ssl_error == SSL_ERROR_WANT_WRITE)) {
				if (++n == block_n) {
					goto ssl_finish_it;
				}

				ms_sleep(10);
			} else { /* code != 0 */
				goto ssl_finish_it;
			}
		}

ssl_finish_it:
		SSL_free(wsh->ssl);
		wsh->ssl = NULL;
	}

	if (wsh->close_sock && wsh->sock != ws_sock_invalid) {
#ifndef WIN32
		close(wsh->sock);
#else
		closesocket(wsh->sock);
#endif
	}

	wsh->sock = ws_sock_invalid;

	return reason * -1;

}


uint64_t hton64(uint64_t val)
{
	if (__BYTE_ORDER == __BIG_ENDIAN) return (val);
	else return __bswap_64(val);
}

uint64_t ntoh64(uint64_t val)
{
	if (__BYTE_ORDER == __BIG_ENDIAN) return (val);
	else return __bswap_64(val);
}


ssize_t ws_read_frame(wsh_t *wsh, ws_opcode_t *oc, uint8_t **data)
{

	ssize_t need = 2;
	char *maskp;
	int ll = 0;
	int frag = 0;
	int blen;

	wsh->body = wsh->bbuffer;
	wsh->packetlen = 0;

 again:
	need = 2;
	maskp = NULL;
	*data = NULL;

	ll = establish_logical_layer(wsh);

	if (ll < 0) {
		return ll;
	}

	if (wsh->down) {
		return -1;
	}

	if (!wsh->handshake) {
		return ws_close(wsh, WS_NONE);
	}

	if ((wsh->datalen = ws_raw_read(wsh, wsh->buffer, 9, wsh->block)) < 0) {
		if (wsh->datalen == -2) {
			return -2;
		}
		return ws_close(wsh, WS_NONE);
	}

	if (wsh->datalen < need) {
		ssize_t bytes = ws_raw_read(wsh, wsh->buffer + wsh->datalen, 9 - wsh->datalen, WS_BLOCK);
		
		if (bytes < 0 || (wsh->datalen += bytes) < need) {
			/* too small - protocol err */
			return ws_close(wsh, WS_NONE);
		}
	}

	*oc = *wsh->buffer & 0xf;

	switch(*oc) {
	case WSOC_CLOSE:
		{
			wsh->plen = wsh->buffer[1] & 0x7f;
			*data = (uint8_t *) &wsh->buffer[2];
			return ws_close(wsh, 1000);
		}
		break;
	case WSOC_CONTINUATION:
	case WSOC_TEXT:
	case WSOC_BINARY:
	case WSOC_PING:
	case WSOC_PONG:
		{
			int fin = (wsh->buffer[0] >> 7) & 1;
			int mask = (wsh->buffer[1] >> 7) & 1;


			if (!fin && *oc != WSOC_CONTINUATION) {
				frag = 1;
			} else if (fin && *oc == WSOC_CONTINUATION) {
				frag = 0;
			}

			if (mask) {
				need += 4;

				if (need > wsh->datalen) {
					ssize_t bytes = ws_raw_read_blocking(wsh, wsh->buffer + wsh->datalen, need - wsh->datalen, 10);
					if (bytes < 0 || (wsh->datalen += bytes) < need) {
						/* too small - protocol err */
						*oc = WSOC_CLOSE;
						return ws_close(wsh, WS_NONE);
					}
				}
			}

			wsh->plen = wsh->buffer[1] & 0x7f;
			wsh->payload = &wsh->buffer[2];

			if (wsh->plen == 127) {
				uint64_t *u64;

				need += 8;

				if (need > wsh->datalen) {
					ssize_t bytes = ws_raw_read_blocking(wsh, wsh->buffer + wsh->datalen, need - wsh->datalen, 10);
					if (bytes < 0 || (wsh->datalen += bytes) < need) {
						/* too small - protocol err */
						*oc = WSOC_CLOSE;
						return ws_close(wsh, WS_NONE);
					}
				}

				u64 = (uint64_t *) wsh->payload;
				wsh->payload += 8;
				wsh->plen = ntoh64(*u64);
			} else if (wsh->plen == 126) {
				uint16_t *u16;

				need += 2;

				if (need > wsh->datalen) {
					ssize_t bytes = ws_raw_read_blocking(wsh, wsh->buffer + wsh->datalen, need - wsh->datalen, 10);
					if (bytes < 0 || (wsh->datalen += bytes) < need) {
						/* too small - protocol err */
						*oc = WSOC_CLOSE;
						return ws_close(wsh, WS_NONE);
					}
				}

				u16 = (uint16_t *) wsh->payload;
				wsh->payload += 2;
				wsh->plen = ntohs(*u16);
			}

			if (mask) {
				maskp = (char *)wsh->payload;
				wsh->payload += 4;
			}

			need = (wsh->plen - (wsh->datalen - need));

			if (need < 0) {
				/* invalid read - protocol err .. */
				*oc = WSOC_CLOSE;
				return ws_close(wsh, WS_NONE);
			}

			blen = wsh->body - wsh->bbuffer;

			if (need + blen > (ssize_t)wsh->bbuflen) {
				void *tmp;

				wsh->bbuflen = need + blen + wsh->rplen;

				if (wsh->payload_size_max && wsh->bbuflen > wsh->payload_size_max) {
					/* size limit */
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_NONE);
				}

				if ((tmp = realloc(wsh->bbuffer, wsh->bbuflen))) {
					wsh->bbuffer = tmp;
				} else {
					abort();
				}

				wsh->body = wsh->bbuffer + blen;
			}

			wsh->rplen = wsh->plen - need;

			if (wsh->rplen) {
				memcpy(wsh->body, wsh->payload, wsh->rplen);
			}

			while(need) {
				ssize_t r = ws_raw_read(wsh, wsh->body + wsh->rplen, need, WS_BLOCK);

				if (r < 1) {
					/* invalid read - protocol err .. */
					*oc = WSOC_CLOSE;
					return ws_close(wsh, WS_NONE);
				}

				wsh->datalen += r;
				wsh->rplen += r;
				need -= r;
			}

			if (mask && maskp) {
				ssize_t i;

				for (i = 0; i < wsh->datalen; i++) {
					wsh->body[i] ^= maskp[i % 4];
				}
			}


			if (*oc == WSOC_PING) {
				ws_write_frame(wsh, WSOC_PONG, wsh->body, wsh->rplen);
				goto again;
			}

			*(wsh->body+wsh->rplen) = '\0';
			wsh->packetlen += wsh->rplen;
			wsh->body += wsh->rplen;

			if (frag) {
				goto again;
			}

			*data = (uint8_t *)wsh->bbuffer;

			//printf("READ[%ld][%d]-----------------------------:\n[%s]\n-------------------------------\n", wsh->packetlen, *oc, (char *)*data);


			return wsh->packetlen;
		}
		break;
	default:
		{
			/* invalid op code - protocol err .. */
			*oc = WSOC_CLOSE;
			return ws_close(wsh, WS_PROTO_ERR);
		}
		break;
	}
}

ssize_t ws_write_frame(wsh_t *wsh, ws_opcode_t oc, void *data, size_t bytes)
{
	uint8_t hdr[14] = { 0 };
	size_t hlen = 2;
	uint8_t *bp;
	ssize_t raw_ret = 0;

	if (wsh->down) {
		errno = EIO;
		return -1;
	}

	//printf("WRITE[%ld]-----------------------------:\n[%s]\n-----------------------------------\n", bytes, (char *) data);

	hdr[0] = (uint8_t)(oc | 0x80);

	if (bytes < 126) {
		hdr[1] = (uint8_t)bytes;
	} else if (bytes < 0x10000) {
		uint16_t *u16;

		hdr[1] = 126;
		hlen += 2;

		u16 = (uint16_t *) &hdr[2];
		*u16 = htons((uint16_t) bytes);

	} else {
		uint64_t *u64;

		hdr[1] = 127;
		hlen += 8;

		u64 = (uint64_t *) &hdr[2];
		*u64 = hton64(bytes);
	}

	if (wsh->write_buffer_len < (hlen + bytes + 1)) {
		void *tmp;

		wsh->write_buffer_len = hlen + bytes + 1;
		if ((tmp = realloc(wsh->write_buffer, wsh->write_buffer_len))) {
			wsh->write_buffer = tmp;
		} else {
			abort();
		}
	}

	bp = (uint8_t *) wsh->write_buffer;
	memcpy(bp, (void *) &hdr[0], hlen);
	memcpy(bp + hlen, data, bytes);

	raw_ret = ws_raw_write(wsh, bp, (hlen + bytes));

	if (raw_ret <= 0 || raw_ret != (ssize_t) (hlen + bytes)) {
		return raw_ret;
	}

	return bytes;
}

#ifdef _MSC_VER

int xp_errno(void)
{
	return WSAGetLastError();
}

int xp_is_blocking(int errcode)
{
	return errcode == WSAEWOULDBLOCK || errcode == WSAEINPROGRESS;
}

#else

int xp_errno(void)
{
	return errno;
}

int xp_is_blocking(int errcode)
{
  return errcode == EAGAIN || errcode == EWOULDBLOCK || errcode == EINPROGRESS || errcode == EINTR || errcode == ETIMEDOUT;
}

#endif
