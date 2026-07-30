/* Second attempt at reproducing EALREADY. The first used loopback, where the
 * handshake completes inside the connectx call even with O_NONBLOCK, so the
 * second connect saw ESTABLISHED and gave EISCONN.
 *
 * To sit in COOKIE_WAIT the peer must not answer. A blackholed address does
 * that: the INIT goes out, nothing comes back, and the association stays in
 * COOKIE_WAIT for the duration of the INIT retransmissions.
 *
 * Note SCTP_STATUS reports asoc->state + 1 (the legacy SCTP_EMPTY=0 offset), so
 * the numbers below are the userspace enum: 2 == COOKIE_WAIT, 4 == ESTABLISHED.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sctp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define SOL_SCTP_ 132

static const char *ustate(int s)
{
	static const char *n[] = { "EMPTY", "CLOSED", "COOKIE_WAIT",
				   "COOKIE_ECHOED", "ESTABLISHED",
				   "SHUTDOWN_PENDING", "SHUTDOWN_SENT",
				   "SHUTDOWN_RECEIVED", "SHUTDOWN_ACK_SENT" };
	return (s >= 0 && s <= 8) ? n[s] : "?";
}

static void show(int fd, const char *when)
{
	struct sctp_status st;
	socklen_t l = sizeof(st);
	memset(&st, 0, sizeof(st));
	if (getsockopt(fd, SOL_SCTP_, SCTP_STATUS, &st, &l) < 0)
		printf("  status %-16s -> %s\n", when, strerror(errno));
	else
		printf("  status %-16s -> %d (%s)\n", when, st.sstat_state,
		       ustate(st.sstat_state));
}

static int connectx3(int fd, struct sockaddr_in *a)
{
	struct { int32_t id; int32_t num; void *addrs; } p;
	socklen_t l = sizeof(p);
	memset(&p, 0, sizeof(p));
	p.num = sizeof(*a);
	p.addrs = a;
	if (getsockopt(fd, SOL_SCTP_, 111, &p, &l) < 0)
		return -errno;
	return p.id;
}

int main(void)
{
	struct sockaddr_in a;
	int fd, r;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	/* TEST-NET-1, guaranteed not to answer. */
	a.sin_addr.s_addr = inet_addr("192.0.2.1");
	a.sin_port = htons(9999);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	r = connectx3(fd, &a);
	printf("first  connectx3 -> %s\n", r < 0 ? strerror(-r) : "ok");
	show(fd, "after first");

	for (int i = 0; i < 3; i++) {
		r = connectx3(fd, &a);
		printf("retry %d          -> %s%s\n", i, r < 0 ? strerror(-r) : "ok",
		       r == -EALREADY ? "   <-- EALREADY" : "");
		show(fd, "after retry");
		usleep(50000);
	}
	close(fd);
	return 0;
}
