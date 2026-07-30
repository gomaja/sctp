/* optprobe measures the socket options this package has not yet bound, on a
 * live kernel, before any Go code is written against them.
 *
 * The RFCs have been wrong about Linux three times in this package already
 * (SCTP_FRAGMENT_INTERLEAVE validation, the level-2 cap, SCTP_REUSE_PORT
 * returning EFAULT rather than being ignored). So every option below is
 * exercised here first and the Go binding is written from what this prints,
 * not from RFC 6458 / 7496 / 6525 / 4895.
 *
 * For each option it reports, on both an unbound and a connected socket:
 *   - the size the kernel accepts and returns
 *   - whether a value written reads back unchanged
 *   - the errno when it refuses
 *
 * Build and run:
 *   docker run --rm --privileged -v "$PWD":/src -w /src sctp-test:latest \
 *     bash -c 'gcc -O0 -o /tmp/optprobe testdata/optprobe/main.c && /tmp/optprobe'
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

/* A connected one-to-one pair, which is all this package creates. Several
 * options behave differently once an association exists, so every case is run
 * against both a fresh socket and a connected one. */
static int pair_up(int *cli, int *srv)
{
	int ln = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
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

static void show_get(const char *label, int fd, int opt, void *buf, socklen_t len)
{
	socklen_t got = len;
	if (getsockopt(fd, SOL_SCTP_, opt, buf, &got) < 0)
		printf("  get %-28s EINVAL/err: %s\n", label, strerror(errno));
	else
		printf("  get %-28s ok, len %u -> %u\n", label, len, got);
}

/* SCTP_DEFAULT_SNDINFO — RFC 6458 s8.1.31, the replacement for the deprecated
 * SCTP_DEFAULT_SEND_PARAM. Checks that a write reads back, which is what a Go
 * setter would rely on. */
static void probe_default_sndinfo(const char *who, int fd)
{
	struct sctp_sndinfo si;
	socklen_t len = sizeof(si);
	printf("SCTP_DEFAULT_SNDINFO [%s] sizeof=%zu\n", who, sizeof(si));
	memset(&si, 0, sizeof(si));
	si.snd_sid = 3;
	si.snd_ppid = htonl(0xabcd);
	si.snd_context = 0x5eed;
	si.snd_flags = 0;
	if (setsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_SNDINFO, &si, len) < 0) {
		printf("  set failed: %s\n", strerror(errno));
	} else {
		memset(&si, 0, sizeof(si));
		if (getsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_SNDINFO, &si, &len) < 0)
			printf("  set ok, get failed: %s\n", strerror(errno));
		else
			printf("  roundtrip sid=%u ppid=0x%x context=0x%x flags=0x%x len=%u\n",
			       si.snd_sid, ntohl(si.snd_ppid), si.snd_context,
			       si.snd_flags, len);
	}
	/* Does a short buffer get rejected, or silently accepted like
	 * SCTP_EVENTS was? That decides whether the Go struct size must be
	 * exact. */
	len = sizeof(si) - 4;
	if (setsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_SNDINFO, &si, len) < 0)
		printf("  short set (%u) rejected: %s\n", len, strerror(errno));
	else
		printf("  short set (%u) ACCEPTED\n", len);
}

/* SCTP_AUTO_ASCONF — RFC 6458 s8.1.21. A plain int per the header, but the
 * kernel only honours it on... something; measure. */
static void probe_auto_asconf(const char *who, int fd)
{
	int v = 1;
	socklen_t len = sizeof(v);
	printf("SCTP_AUTO_ASCONF [%s]\n", who);
	if (setsockopt(fd, SOL_SCTP_, SCTP_AUTO_ASCONF, &v, len) < 0) {
		printf("  set 1 failed: %s\n", strerror(errno));
	} else {
		v = -1;
		if (getsockopt(fd, SOL_SCTP_, SCTP_AUTO_ASCONF, &v, &len) < 0)
			printf("  set ok, get failed: %s\n", strerror(errno));
		else
			printf("  set 1 -> get %d (len %u)\n", v, len);
	}
}

/* RFC 7496 PR-SCTP. SCTP_PR_SUPPORTED negotiates the extension;
 * SCTP_DEFAULT_PRINFO sets the default policy and lifetime. */
static void probe_prsctp(const char *who, int fd)
{
	int v;
	socklen_t len;
	struct sctp_default_prinfo pi;
	struct sctp_prstatus ps;

	printf("SCTP_PR_SUPPORTED [%s]\n", who);
	v = 1;
	len = sizeof(v);
	if (setsockopt(fd, SOL_SCTP_, SCTP_PR_SUPPORTED, &v, len) < 0) {
		printf("  set 1 failed: %s\n", strerror(errno));
	} else {
		v = -1;
		if (getsockopt(fd, SOL_SCTP_, SCTP_PR_SUPPORTED, &v, &len) < 0)
			printf("  get failed: %s\n", strerror(errno));
		else
			printf("  set 1 -> get %d (len %u)\n", v, len);
	}
	/* An assoc_value shape is also plausible here; find out which the
	 * kernel wants so the Go side does not guess. */
	{
		struct sctp_assoc_value av;
		socklen_t al = sizeof(av);
		memset(&av, 0, sizeof(av));
		av.assoc_value = 1;
		if (setsockopt(fd, SOL_SCTP_, SCTP_PR_SUPPORTED, &av, al) < 0)
			printf("  assoc_value set failed: %s\n", strerror(errno));
		else
			printf("  assoc_value set ACCEPTED (len %u)\n", al);
	}

	printf("SCTP_DEFAULT_PRINFO [%s] sizeof=%zu\n", who, sizeof(pi));
	memset(&pi, 0, sizeof(pi));
	pi.pr_policy = SCTP_PR_SCTP_TTL;
	pi.pr_value = 5000;
	len = sizeof(pi);
	if (setsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_PRINFO, &pi, len) < 0) {
		printf("  set TTL/5000 failed: %s\n", strerror(errno));
	} else {
		memset(&pi, 0, sizeof(pi));
		if (getsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_PRINFO, &pi, &len) < 0)
			printf("  get failed: %s\n", strerror(errno));
		else
			printf("  roundtrip policy=0x%x value=%u len=%u\n",
			       pi.pr_policy, pi.pr_value, len);
	}
	/* Is an out-of-range policy policed, or accepted like the interleave
	 * level was? */
	memset(&pi, 0, sizeof(pi));
	pi.pr_policy = 0x40;
	pi.pr_value = 1;
	if (setsockopt(fd, SOL_SCTP_, SCTP_DEFAULT_PRINFO, &pi, sizeof(pi)) < 0)
		printf("  bogus policy 0x40 rejected: %s\n", strerror(errno));
	else
		printf("  bogus policy 0x40 ACCEPTED\n");

	printf("SCTP_PR_STREAM_STATUS [%s] sizeof=%zu\n", who, sizeof(ps));
	memset(&ps, 0, sizeof(ps));
	ps.sprstat_policy = SCTP_PR_SCTP_TTL;
	ps.sprstat_sid = 0;
	len = sizeof(ps);
	if (getsockopt(fd, SOL_SCTP_, SCTP_PR_STREAM_STATUS, &ps, &len) < 0)
		printf("  get failed: %s\n", strerror(errno));
	else
		printf("  unsent=%llu sent=%llu len=%u\n",
		       (unsigned long long)ps.sprstat_abandoned_unsent,
		       (unsigned long long)ps.sprstat_abandoned_sent, len);
}

/* RFC 6525 stream reconfiguration. */
static void probe_reconfig(const char *who, int fd)
{
	int v;
	socklen_t len = sizeof(v);
	struct sctp_add_streams as;

	printf("SCTP_RECONFIG_SUPPORTED [%s]\n", who);
	v = 1;
	if (setsockopt(fd, SOL_SCTP_, SCTP_RECONFIG_SUPPORTED, &v, len) < 0)
		printf("  set 1 failed: %s\n", strerror(errno));
	else {
		v = -1;
		if (getsockopt(fd, SOL_SCTP_, SCTP_RECONFIG_SUPPORTED, &v, &len) < 0)
			printf("  get failed: %s\n", strerror(errno));
		else
			printf("  set 1 -> get %d (len %u)\n", v, len);
	}

	printf("SCTP_ENABLE_STREAM_RESET [%s]\n", who);
	v = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_RESET_ASSOC_REQ |
	    SCTP_ENABLE_CHANGE_ASSOC_REQ;
	len = sizeof(v);
	if (setsockopt(fd, SOL_SCTP_, SCTP_ENABLE_STREAM_RESET, &v, len) < 0)
		printf("  set 0x%x failed: %s\n", v, strerror(errno));
	else {
		v = -1;
		if (getsockopt(fd, SOL_SCTP_, SCTP_ENABLE_STREAM_RESET, &v, &len) < 0)
			printf("  get failed: %s\n", strerror(errno));
		else
			printf("  set mask -> get 0x%x (len %u)\n", v, len);
	}

	printf("SCTP_ADD_STREAMS [%s] sizeof=%zu\n", who, sizeof(as));
	memset(&as, 0, sizeof(as));
	as.sas_instrms = 2;
	as.sas_outstrms = 2;
	if (setsockopt(fd, SOL_SCTP_, SCTP_ADD_STREAMS, &as, sizeof(as)) < 0)
		printf("  add 2/2 failed: %s\n", strerror(errno));
	else
		printf("  add 2/2 ok\n");
}

/* RFC 4895 AUTH. May be compiled out entirely; that is the first thing to
 * learn, because a binding for an option the kernel never supports is dead
 * code. */
static void probe_auth(const char *who, int fd)
{
	struct sctp_hmacalgo *ha;
	unsigned char buf[256];
	socklen_t len;
	int v;

	printf("SCTP_AUTH_ACTIVE_KEY / HMAC_IDENT [%s]\n", who);
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

	{
		struct sctp_authkeyid ak;
		memset(&ak, 0, sizeof(ak));
		len = sizeof(ak);
		if (getsockopt(fd, SOL_SCTP_, SCTP_AUTH_ACTIVE_KEY, &ak, &len) < 0)
			printf("  ACTIVE_KEY get failed: %s\n", strerror(errno));
		else
			printf("  ACTIVE_KEY keynumber=%u len=%u\n",
			       ak.scact_keynumber, len);
	}

	{
		/* Setting a key is the operation a caller actually wants; if AUTH
		 * is disabled this is where it shows. */
		unsigned char kb[sizeof(struct sctp_authkey) + 8];
		struct sctp_authkey *k = (struct sctp_authkey *)kb;
		memset(kb, 0, sizeof(kb));
		k->sca_keynumber = 1;
		k->sca_keylength = 8;
		memcpy(k->sca_key, "12345678", 8);
		if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_KEY, kb, sizeof(kb)) < 0)
			printf("  AUTH_KEY set failed: %s\n", strerror(errno));
		else
			printf("  AUTH_KEY set ok\n");
	}

	v = 1;
	if (getsockopt(fd, SOL_SCTP_, SCTP_LOCAL_AUTH_CHUNKS, buf, (len = sizeof(buf), &len)) < 0)
		printf("  LOCAL_AUTH_CHUNKS get failed: %s\n", strerror(errno));
	else
		printf("  LOCAL_AUTH_CHUNKS len=%u\n", len);
	(void)v;
}

/* Read-only association introspection. */
static void probe_assoc_info(const char *who, int fd)
{
	struct sctp_assoc_stats st;
	socklen_t len = sizeof(st);
	unsigned char buf[512];

	printf("SCTP_GET_ASSOC_STATS [%s] sizeof=%zu\n", who, sizeof(st));
	memset(&st, 0, sizeof(st));
	if (getsockopt(fd, SOL_SCTP_, SCTP_GET_ASSOC_STATS, &st, &len) < 0)
		printf("  get failed: %s\n", strerror(errno));
	else
		printf("  opackets=%llu ipackets=%llu maxrto=%llu len=%u\n",
		       (unsigned long long)st.sas_opackets,
		       (unsigned long long)st.sas_ipackets,
		       (unsigned long long)st.sas_maxrto, len);

	printf("SCTP_GET_ASSOC_NUMBER [%s]\n", who);
	{
		uint32_t n = 0;
		len = sizeof(n);
		if (getsockopt(fd, SOL_SCTP_, SCTP_GET_ASSOC_NUMBER, &n, &len) < 0)
			printf("  get failed: %s\n", strerror(errno));
		else
			printf("  number=%u len=%u\n", n, len);
	}

	printf("SCTP_PEER_ADDR_THLDS [%s] sizeof=%zu\n", who,
	       sizeof(struct sctp_paddrthlds));
	{
		struct sctp_paddrthlds th;
		memset(&th, 0, sizeof(th));
		len = sizeof(th);
		if (getsockopt(fd, SOL_SCTP_, SCTP_PEER_ADDR_THLDS, &th, &len) < 0) {
			printf("  get failed: %s\n", strerror(errno));
		} else {
			printf("  pathmaxrxt=%u pfthld=%u len=%u\n",
			       th.spt_pathmaxrxt, th.spt_pathpfthld, len);
			th.spt_pathpfthld = 3;
			if (setsockopt(fd, SOL_SCTP_, SCTP_PEER_ADDR_THLDS, &th,
				       sizeof(th)) < 0)
				printf("  set pfthld=3 failed: %s\n", strerror(errno));
			else
				printf("  set pfthld=3 ok\n");
		}
	}
	(void)buf;
}

int main(void)
{
	int fresh, cli, srv;

	fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (fresh < 0) {
		perror("socket");
		return 1;
	}
	if (pair_up(&cli, &srv) < 0) {
		perror("pair_up");
		return 1;
	}

	printf("======== FRESH (unbound, unconnected) ========\n");
	probe_default_sndinfo("fresh", fresh);
	probe_auto_asconf("fresh", fresh);
	probe_prsctp("fresh", fresh);
	probe_reconfig("fresh", fresh);
	probe_auth("fresh", fresh);
	probe_assoc_info("fresh", fresh);

	printf("\n======== CONNECTED (one-to-one association) ========\n");
	probe_default_sndinfo("conn", cli);
	probe_auto_asconf("conn", cli);
	probe_prsctp("conn", cli);
	probe_reconfig("conn", cli);
	probe_auth("conn", cli);
	probe_assoc_info("conn", cli);

	close(fresh);
	close(cli);
	close(srv);
	return 0;
}
