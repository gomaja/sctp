/* shapes.c settles two questions the first optprobe run raised.
 *
 * 1. SCTP_PR_SUPPORTED, SCTP_RECONFIG_SUPPORTED and SCTP_ENABLE_STREAM_RESET
 *    all rejected a plain int with EINVAL but accepted an 8-byte
 *    sctp_assoc_value. RFC 7496 s4.5 and RFC 6525 s6.3 both describe these as
 *    taking an on/off value, and the kernel header offers no struct. So the
 *    question is whether assoc_value is merely accepted by length or is
 *    actually the shape the kernel reads -- i.e. does the value round-trip,
 *    and does the assoc_id field matter.
 *
 * 2. SCTP_AUTH_* returned EACCES on every call because net.sctp.auth_enable
 *    was 0. With it set to 1, do the options work, and what do they need?
 *
 * Run with auth_enable already set to 1.
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

static int pair_up(int *cli, int *srv)
{
	int ln = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (ln < 0 || bind(ln, (struct sockaddr *)&a, sizeof(a)) < 0 ||
	    listen(ln, 1) < 0 || getsockname(ln, (struct sockaddr *)&a, &alen) < 0)
		return -1;
	*cli = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (*cli < 0 || connect(*cli, (struct sockaddr *)&a, sizeof(a)) < 0)
		return -1;
	*srv = accept(ln, NULL, NULL);
	close(ln);
	return *srv < 0 ? -1 : 0;
}

/* Write via assoc_value, read back both ways, and report which lengths the
 * kernel will hand back. If get also insists on 8 bytes then assoc_value is
 * the real shape and a Go int-based accessor would be wrong. */
static void shape(const char *name, int opt, int fd, uint32_t val)
{
	struct sctp_assoc_value av;
	socklen_t len;
	int iv;

	printf("%s\n", name);

	memset(&av, 0, sizeof(av));
	av.assoc_value = val;
	if (setsockopt(fd, SOL_SCTP_, opt, &av, sizeof(av)) < 0) {
		printf("  assoc_value set %u failed: %s\n", val, strerror(errno));
		return;
	}
	printf("  assoc_value set %u ok\n", val);

	memset(&av, 0, sizeof(av));
	len = sizeof(av);
	if (getsockopt(fd, SOL_SCTP_, opt, &av, &len) < 0)
		printf("  assoc_value get failed: %s\n", strerror(errno));
	else
		printf("  assoc_value get -> %u (assoc_id=%d len=%u)\n",
		       av.assoc_value, av.assoc_id, len);

	iv = -1;
	len = sizeof(iv);
	if (getsockopt(fd, SOL_SCTP_, opt, &iv, &len) < 0)
		printf("  int get failed: %s\n", strerror(errno));
	else
		printf("  int get -> %d (len %u)\n", iv, len);

	/* A garbage assoc_id on a one-to-one socket: ignored, or ENOENT? This
	 * decides whether the Go side must zero it or may leave it alone. */
	memset(&av, 0, sizeof(av));
	av.assoc_value = val;
	av.assoc_id = 0x7fffffff;
	if (setsockopt(fd, SOL_SCTP_, opt, &av, sizeof(av)) < 0)
		printf("  bogus assoc_id rejected: %s\n", strerror(errno));
	else
		printf("  bogus assoc_id IGNORED\n");
}

static void auth(const char *who, int fd)
{
	unsigned char buf[256];
	socklen_t len;
	struct sctp_hmacalgo *ha;
	struct sctp_authkeyid ak;
	struct sctp_authchunk ac;

	printf("AUTH [%s]\n", who);

	len = sizeof(buf);
	memset(buf, 0, sizeof(buf));
	if (getsockopt(fd, SOL_SCTP_, SCTP_HMAC_IDENT, buf, &len) < 0) {
		printf("  HMAC_IDENT get failed: %s\n", strerror(errno));
	} else {
		ha = (struct sctp_hmacalgo *)buf;
		printf("  HMAC_IDENT num=%u len=%u:", ha->shmac_num_idents, len);
		for (unsigned i = 0; i < ha->shmac_num_idents && i < 8; i++)
			printf(" %u", ha->shmac_idents[i]);
		printf("\n");
	}

	/* SCTP_AUTH_CHUNK is set-only and must precede the association per
	 * RFC 4895 s6.1; check whether the kernel enforces that. */
	memset(&ac, 0, sizeof(ac));
	ac.sauth_chunk = 0; /* DATA */
	if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_CHUNK, &ac, sizeof(ac)) < 0)
		printf("  AUTH_CHUNK(DATA) set failed: %s\n", strerror(errno));
	else
		printf("  AUTH_CHUNK(DATA) set ok\n");

	{
		unsigned char kb[sizeof(struct sctp_authkey) + 8];
		struct sctp_authkey *k = (struct sctp_authkey *)kb;
		memset(kb, 0, sizeof(kb));
		k->sca_keynumber = 1;
		k->sca_keylength = 8;
		memcpy(k->sca_key, "12345678", 8);
		if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_KEY, kb, sizeof(kb)) < 0)
			printf("  AUTH_KEY set failed: %s\n", strerror(errno));
		else
			printf("  AUTH_KEY(1) set ok\n");
		/* Does the kernel validate keylength against the buffer it was
		 * given? A mismatch here would be a read past the option. */
		memset(kb, 0, sizeof(kb));
		k->sca_keynumber = 2;
		k->sca_keylength = 200;
		if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_KEY, kb, sizeof(kb)) < 0)
			printf("  AUTH_KEY overlong keylength rejected: %s\n",
			       strerror(errno));
		else
			printf("  AUTH_KEY overlong keylength ACCEPTED\n");
	}

	memset(&ak, 0, sizeof(ak));
	ak.scact_keynumber = 1;
	if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_ACTIVE_KEY, &ak, sizeof(ak)) < 0)
		printf("  ACTIVE_KEY(1) set failed: %s\n", strerror(errno));
	else
		printf("  ACTIVE_KEY(1) set ok\n");

	memset(&ak, 0, sizeof(ak));
	len = sizeof(ak);
	if (getsockopt(fd, SOL_SCTP_, SCTP_AUTH_ACTIVE_KEY, &ak, &len) < 0)
		printf("  ACTIVE_KEY get failed: %s\n", strerror(errno));
	else
		printf("  ACTIVE_KEY get -> %u (len %u)\n", ak.scact_keynumber, len);

	/* Deleting the active key must fail per RFC 4895 s6.4. */
	memset(&ak, 0, sizeof(ak));
	ak.scact_keynumber = 1;
	if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_DELETE_KEY, &ak, sizeof(ak)) < 0)
		printf("  DELETE active key rejected: %s\n", strerror(errno));
	else
		printf("  DELETE active key ACCEPTED\n");

	len = sizeof(buf);
	memset(buf, 0, sizeof(buf));
	if (getsockopt(fd, SOL_SCTP_, SCTP_LOCAL_AUTH_CHUNKS, buf, &len) < 0)
		printf("  LOCAL_AUTH_CHUNKS get failed: %s\n", strerror(errno));
	else {
		struct sctp_authchunks *c = (struct sctp_authchunks *)buf;
		printf("  LOCAL_AUTH_CHUNKS len=%u num=%u:", len,
		       (unsigned)(len - sizeof(sctp_assoc_t)));
		for (unsigned i = 0; i < len - sizeof(sctp_assoc_t) && i < 8; i++)
			printf(" %u", c->gauth_chunks[i]);
		printf("\n");
	}

	len = sizeof(buf);
	memset(buf, 0, sizeof(buf));
	if (getsockopt(fd, SOL_SCTP_, SCTP_PEER_AUTH_CHUNKS, buf, &len) < 0)
		printf("  PEER_AUTH_CHUNKS get failed: %s\n", strerror(errno));
	else
		printf("  PEER_AUTH_CHUNKS len=%u\n", len);
}

int main(void)
{
	int fresh, cli, srv;

	fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (fresh < 0) {
		perror("socket");
		return 1;
	}

	printf("======== shapes, FRESH ========\n");
	shape("SCTP_PR_SUPPORTED", SCTP_PR_SUPPORTED, fresh, 1);
	shape("SCTP_RECONFIG_SUPPORTED", SCTP_RECONFIG_SUPPORTED, fresh, 1);
	shape("SCTP_ENABLE_STREAM_RESET", SCTP_ENABLE_STREAM_RESET, fresh,
	      SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_RESET_ASSOC_REQ |
		      SCTP_ENABLE_CHANGE_ASSOC_REQ);
	auth("fresh", fresh);
	close(fresh);

	if (pair_up(&cli, &srv) < 0) {
		perror("pair_up");
		return 1;
	}
	printf("\n======== shapes, CONNECTED ========\n");
	shape("SCTP_PR_SUPPORTED", SCTP_PR_SUPPORTED, cli, 1);
	shape("SCTP_RECONFIG_SUPPORTED", SCTP_RECONFIG_SUPPORTED, cli, 1);
	shape("SCTP_ENABLE_STREAM_RESET", SCTP_ENABLE_STREAM_RESET, cli,
	      SCTP_ENABLE_RESET_STREAM_REQ);
	auth("conn", cli);

	/* With reset enabled on a live association, does ADD_STREAMS work now? */
	{
		struct sctp_add_streams as;
		memset(&as, 0, sizeof(as));
		as.sas_instrms = 2;
		as.sas_outstrms = 2;
		if (setsockopt(cli, SOL_SCTP_, SCTP_ADD_STREAMS, &as,
			       sizeof(as)) < 0)
			printf("ADD_STREAMS after enable failed: %s\n",
			       strerror(errno));
		else
			printf("ADD_STREAMS after enable ok\n");
	}

	close(cli);
	close(srv);
	return 0;
}
