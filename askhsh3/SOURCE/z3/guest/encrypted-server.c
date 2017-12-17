/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

#define DATA_SIZE       256
#define BLOCK_SIZE      16

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

void delete_from_array (int i, int *fd, int fcount) {
	if (i + 1 == fcount) return;
	int j;
	for (j = i + 1; j < fcount; j++)
		fd[j - 1] = fd[j];
}

int main(void) {
	int i, fcount = 0,
			fdmax, sent,
			sd, newsd,
			cnt, flag,
			*fd;
	unsigned char buf[DATA_SIZE];
	char addrstr[INET_ADDRSTRLEN];			 
	ssize_t ret;
	socklen_t len;
	struct sockaddr_in sa;
	fd_set fd_read, fd_write,
				 master_chef;

	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	fcntl(sd, F_SETFL, O_NONBLOCK);

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	fdmax = sd;
	FD_ZERO(&master_chef);
	FD_SET(sd, &master_chef);

	cnt = 0; flag = 0;
	fd = malloc (sizeof(int));
	len = sizeof(struct sockaddr_in);
	/* Loop forever, accept()ing connections */
	for (;;) {
		/* Accept an incoming connection */
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) > 0) {
			if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
				perror("could not format IP address");
				exit(1);
			}
			fprintf(stderr, "Incoming connection from %s:%d\n",
				addrstr, ntohs(sa.sin_port));
			if (newsd > fdmax) fdmax = newsd;
			FD_SET(newsd, &master_chef);
			fd = realloc (fd, (fcount + 1) * sizeof(int));
			fd[fcount++] = newsd;
			fprintf(stdout, "Set new socket!\n");
		}

		fd_read = fd_write = master_chef;
		ret = select(fdmax + 1, &fd_read, &fd_write, NULL, NULL);
		if (ret < 0) {
			perror("select");
			exit(1);
		} else if (ret > 0) {
			if (FD_ISSET(sd, &fd_read)) continue;
			for (i = 0; i < fcount; i++) {
				if (FD_ISSET(fd[i], &fd_read)) {
					while (cnt < DATA_SIZE) {
						ret = read(fd[i], buf, DATA_SIZE);
						sent = fd[i];
						if (ret <= 0) {
							FD_CLR(fd[i], &master_chef);
							close(fd[i]);
							delete_from_array(i, fd, fcount);
							fcount--;
							if (ret < 0)
								perror("read from remote peer failed");
							else {
								fprintf(stderr, "Peer went away\n");
								break;
							}
						}
						cnt += ret;
					}
				}
			}
			for (i = 0; i < fcount; i++) {
				if (FD_ISSET(fd[i], &fd_write)) {
					if (sent != fd[i]) {
						flag = 1;
						if (cnt > 0)
							if (insist_write(fd[i], buf, DATA_SIZE) != DATA_SIZE) {
								perror("write to peers");
								exit(1);
							}
					}
				}
			}
			if (flag == 1 || fcount == 1) { cnt = 0; flag = 0; }
		}
	}
	/* Make sure we don't leak open files */
	if (close(newsd) < 0)
		perror("close");

	/* This will never happen */
	return 1;
}