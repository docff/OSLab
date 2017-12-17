#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>

#include <crypto/cryptodev.h>

#include "socket-common.h"

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE				16  /* AES128 */

void encrypt (int cd, struct session_op *sess, unsigned char *iv, unsigned char *indata,
							unsigned char *outdata, ssize_t cnt) {
	unsigned char temp_data[DATA_SIZE];
	struct crypt_op cryp;	
	memset(&cryp, 0, sizeof(cryp));

	struct session_op sess_t;
	memcpy (&sess_t, sess, sizeof(sess_t));

	memset (temp_data, 0, DATA_SIZE);
	memcpy (temp_data, indata, cnt);

	cryp.ses = sess_t.ses;
	cryp.len = DATA_SIZE;
	cryp.src = temp_data;
	cryp.dst = outdata;
	cryp.iv = iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}
	return;
}

void decrypt (int cd, struct session_op *sess, unsigned char *iv, unsigned char *indata,
							unsigned char *outdata, ssize_t cnt) {
	unsigned char temp_data[DATA_SIZE];
	struct crypt_op cryp;	
	memset(&cryp, 0, sizeof(cryp));

	struct session_op sess_t;
	memcpy (&sess_t, sess, sizeof(sess_t));

	memset (temp_data, 0, DATA_SIZE);
	memcpy (temp_data, indata, cnt);

	cryp.ses = sess_t.ses;
	cryp.len = DATA_SIZE;
	cryp.src = temp_data;
	cryp.dst = outdata;
	cryp.iv = iv;
	cryp.op = COP_DECRYPT;

	if (ioctl(cd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}
	return;
}

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
    ret = write(fd, buf, cnt);
    if (ret < 0)
            return ret;
    buf += ret;
    cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[]) {
	int cntstd, cntsd, i,
			cd, sd, port,
			fdmax, *fd;
	ssize_t ret;
	unsigned char bufstd[DATA_SIZE],
								bufsd[DATA_SIZE],
								msg[DATA_SIZE];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	fd_set fd_read, fd_write,
				 master_chef;
	struct {
		unsigned char
				in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;
	struct session_op sess;
	memset(&sess, 0, sizeof(sess));

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}

	hostname = argv[1];
	port = atoi(argv[2]);
	if (sizeof(port) > 16) {
		perror("too big of a port");
		exit(1);
	}

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if (!(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Opening device for read-write */
	cd = open("/dev/crypto", O_RDWR);
	if (cd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	memcpy (data.key, PSK, KEY_SIZE);
	memcpy (data.iv, PIV, BLOCK_SIZE);

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(cd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}

	fdmax = 0;
	if (sd > fdmax) fdmax = sd;
	fd = malloc (2 * sizeof(int));
	fd[0] = 0; fd[1] = sd;
	FD_ZERO(&fd_read); FD_ZERO(&fd_write); FD_ZERO(&master_chef);
	FD_SET(fd[0], &master_chef); FD_SET(fd[1], &master_chef);

	cntstd = cntsd = 0;
	for (;;) {
		fd_read = fd_write = master_chef;	
		ret = select(fdmax + 1, &fd_read, &fd_write, NULL, NULL);
		if (ret < 0) {
			perror("select");
			exit(1);
		} else if (ret > 0) {
			for (i = 0; i < 2; i++) {
				if (FD_ISSET(fd[i], &fd_read)) {
					if (fd[i] == 0) {
						ret = read(fd[i], bufstd, sizeof(bufstd));
						if (ret == 0) {
							if (shutdown(sd, SHUT_WR) < 0) {
								perror("shutdown");
								exit(1);
							}
							if (ioctl(cd, CIOCFSESSION, &sess.ses)) {
								perror("ioctl(CIOCFSESSION)");
								exit(1);
							}
							if (close(cd) < 0) {
								perror("close(cd)");
								exit(1);
							}
							fprintf(stderr, "Chat session has ended!.\n");
							return 0;
						}
						cntstd = ret;
					} else {
						ret = insist_read(fd[i], bufsd, DATA_SIZE);
						cntsd = ret;
					}
					if (ret < 0) {
						perror("read stdin");
						exit(1);
					}
				}
			}
			for (i = 0; i < 2; i++) {
				if (FD_ISSET(fd[i], &fd_write)) {
					if (fd[i] == 0) {
						if (cntsd > 0) {
							decrypt (cd, &sess, data.iv, bufsd, msg, DATA_SIZE);
							if (insist_write(fd[i], msg, DATA_SIZE) != DATA_SIZE) {
								perror("write to server");
								exit(1);
							}
							cntsd = 0;
						}
					} else {
						if (cntstd > 0) {
							encrypt (cd, &sess, data.iv, bufstd, msg, cntstd);
							if (insist_write(fd[i], msg, DATA_SIZE) != DATA_SIZE) {
								perror("write to server");
								exit(1);
							}
							cntstd = 0;
						}
					}
				}
			}
		}
	}
}