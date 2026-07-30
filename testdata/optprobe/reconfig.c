/* reconfig.c confirms the one surprising result from shapes.c:
 * SCTP_RECONFIG_SUPPORTED set to 1 on an already-connected socket returns
 * success but reads back 0, while the same set on a fresh socket sticks.
 *
 * The suspicion is that the flag is only meaningful before the INIT that
 * negotiates the extension, and that a post-connect set is silently dropped.
 * If so, a caller enabling it after connect gets nothing and no error -- worth
 * documenting at the setter.
 *
 * This distinguishes three explanations:
 *   (a) post-connect set is dropped   -> fresh sticks, connected reads 0
 *   (b) it reflects peer negotiation  -> both ends enabled before connect
 *                                        should read 1 after connect
 *   (c) the earlier read was a fluke  -> repeated reads disagree
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sctp.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SOL_SCTP_ 132

static int get_rc(int fd, uint32_t *out)
{
	struct sctp_assoc_value av;
	socklen_t len = sizeof(av);
	memset(&av, 0, sizeof(av));
	if (getsockopt(fd, SOL_SCTP_, SCTP_RECONFIG_SUPPORTED, &av, &len) < 0)
		return -1;
	*out = av.assoc_value;
	return 0;
}

static int set_rc(int fd, uint32_t v)
{
	struct sctp_assoc_value av;
	memset(&av, 0, sizeof(av));
	av.assoc_value = v;
	return setsockopt(fd, SOL_SCTP_, SCTP_RECONFIG_SUPPORTED, &av,
			  sizeof(av));
}

/* enable_before decides whether each end turns the extension on prior to the
 * handshake, which is what separates explanation (a) from (b). */
static void run(const char *label, int enable_listener, int enable_client)
{
	int ln, cli, srv;
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	uint32_t v;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ln = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (enable_listener && set_rc(ln, 1) < 0) {
		printf("%s: listener set failed: %s\n", label, strerror(errno));
		return;
	}
	if (bind(ln, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(ln, 1) < 0 ||
	    getsockname(ln, (struct sockaddr *)&a, &alen) < 0) {
		printf("%s: listen setup failed: %s\n", label, strerror(errno));
		return;
	}

	cli = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (enable_client && set_rc(cli, 1) < 0) {
		printf("%s: client set failed: %s\n", label, strerror(errno));
		return;
	}
	if (get_rc(cli, &v) == 0)
		printf("%s: client before connect -> %u\n", label, v);

	if (connect(cli, (struct sockaddr *)&a, sizeof(a)) < 0) {
		printf("%s: connect failed: %s\n", label, strerror(errno));
		return;
	}
	srv = accept(ln, NULL, NULL);

	if (get_rc(cli, &v) == 0)
		printf("%s: client after connect  -> %u\n", label, v);
	if (srv >= 0 && get_rc(srv, &v) == 0)
		printf("%s: server after accept   -> %u\n", label, v);

	/* Now set it post-connect and read it straight back, three times, to
	 * rule out a transient. */
	for (int i = 0; i < 3; i++) {
		if (set_rc(cli, 1) < 0) {
			printf("%s: post-connect set #%d failed: %s\n", label, i,
			       strerror(errno));
			break;
		}
		if (get_rc(cli, &v) == 0)
			printf("%s: post-connect set#%d -> get %u\n", label, i, v);
	}

	close(cli);
	if (srv >= 0)
		close(srv);
	close(ln);
}

int main(void)
{
	run("neither", 0, 0);
	printf("\n");
	run("client-only", 0, 1);
	printf("\n");
	run("both", 1, 1);
	return 0;
}
