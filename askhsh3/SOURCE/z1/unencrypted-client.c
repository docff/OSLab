#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>

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

int main(int argc, char *argv[])
{
	int sd, port, *fd, fdmax, i, cntstd, cntsd;
	ssize_t ret;
	char bufstd[100], bufsd[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	fd_set fd_read, fd_write,
					master_chef;

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
						ret = read(fd[i], bufstd + cntstd, sizeof(bufstd) - cntstd - 1);
						if (ret == 0) {
							if (shutdown(sd, SHUT_WR) < 0) {
								perror("shutdown");
								exit(1);
							}
							fprintf(stderr, "Chat session has ended!.\n");
							return 0;
						}
						cntstd += ret;
						bufstd[cntstd] = '\0';
					} else {
						ret = read(fd[i], bufsd + cntsd, sizeof(bufsd) - cntsd - 1);
						cntsd += ret;
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
							if (insist_write(fd[i], bufsd, cntsd) != cntsd) {
								perror("write to server");
								exit(1);
							}
							cntsd = 0;
						}
					} else {
						if (cntstd > 0) {
							if (insist_write(fd[i], bufstd, cntstd) != cntstd) {
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