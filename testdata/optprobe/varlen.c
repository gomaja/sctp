/* varlen.c investigates the two options left open because they carry
 * variable-length payloads and the obvious fixed-size call was refused.
 *
 * 1. SCTP_RESET_STREAMS returned EINVAL for every fixed-size form tried. The
 *    open question is whether the option is unusable on a one-to-one socket or
 *    whether the earlier attempts simply got the length or the preconditions
 *    wrong -- the same mistake that nearly caused SCTP_ADD_STREAMS to be written
 *    off as unsupported. srs_number_streams == 0 is documented as "all streams",
 *    so a bare struct with no trailing list ought to be legal.
 *
 * 2. SCTP_AUTH_KEY takes struct sctp_authkey with a flexible key array. What a
 *    Go binding needs to know: does the kernel validate sca_keylength against
 *    the option length, what is the maximum key it accepts, and does the
 *    keynumber space have a reserved value.
 *
 * Every case prints the errno so a refusal is distinguishable from a wrong
 * assumption about the shape.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sctp.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SOL_SCTP_ 132

static int set_av(int fd, int opt, uint32_t v)
{
	struct sctp_assoc_value a;
	memset(&a, 0, sizeof(a));
	a.assoc_value = v;
	return setsockopt(fd, SOL_SCTP_, opt, &a, sizeof(a));
}

static int get_av(int fd, int opt, uint32_t *v)
{
	struct sctp_assoc_value a;
	socklen_t l = sizeof(a);
	memset(&a, 0, sizeof(a));
	if (getsockopt(fd, SOL_SCTP_, opt, &a, &l) < 0)
		return -1;
	*v = a.assoc_value;
	return 0;
}

/* pair_up brings up an association, optionally negotiating the stream
 * reconfiguration extension on both ends first. Doing it on both ends before
 * connect is the precondition SCTP_ADD_STREAMS turned out to need, so
 * SCTP_RESET_STREAMS is tried the same way rather than on a bare association. */
static int pair_up(int *cli, int *srv, int reconf)
{
	int ln;
	struct sockaddr_in a;
	socklen_t al = sizeof(a);

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ln = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (ln < 0)
		return -1;
	if (reconf) {
		set_av(ln, SCTP_RECONFIG_SUPPORTED, 1);
		set_av(ln, SCTP_ENABLE_STREAM_RESET, SCTP_ENABLE_STRRESET_MASK);
	}
	if (bind(ln, (struct sockaddr *)&a, sizeof(a)) < 0 ||
	    listen(ln, 1) < 0 ||
	    getsockname(ln, (struct sockaddr *)&a, &al) < 0)
		return -1;

	*cli = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	if (*cli < 0)
		return -1;
	if (reconf) {
		set_av(*cli, SCTP_RECONFIG_SUPPORTED, 1);
		set_av(*cli, SCTP_ENABLE_STREAM_RESET, SCTP_ENABLE_STRRESET_MASK);
	}
	if (connect(*cli, (struct sockaddr *)&a, sizeof(a)) < 0)
		return -1;
	*srv = accept(ln, NULL, NULL);
	close(ln);
	return *srv < 0 ? -1 : 0;
}

/* Send one message so the streams have sequence numbers worth resetting; the
 * kernel may refuse a reset on a stream that has never been used. */
static void warm_stream(int fd, uint16_t sid)
{
	/* sendmsg with an SCTP_SNDRCV cmsg rather than sctp_send(), to keep this
	 * probe free of libsctp -- the test image does not carry its headers. */
	char payload[] = "warm";
	struct iovec iov = { .iov_base = payload, .iov_len = 4 };
	char cbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo))];
	struct msghdr m;
	struct cmsghdr *c;
	struct sctp_sndrcvinfo *info;

	memset(&m, 0, sizeof(m));
	memset(cbuf, 0, sizeof(cbuf));
	m.msg_iov = &iov;
	m.msg_iovlen = 1;
	m.msg_control = cbuf;
	m.msg_controllen = sizeof(cbuf);
	c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = IPPROTO_SCTP;
	c->cmsg_type = SCTP_SNDRCV;
	c->cmsg_len = CMSG_LEN(sizeof(*info));
	info = (struct sctp_sndrcvinfo *)CMSG_DATA(c);
	info->sinfo_stream = sid;

	if (sendmsg(fd, &m, 0) < 0)
		printf("  (warm_stream sid=%u failed: %s)\n", sid, strerror(errno));
}

static void reset_streams(const char *label, int fd, uint16_t nstreams,
			  const uint16_t *list, size_t optlen)
{
	unsigned char buf[sizeof(struct sctp_reset_streams) + 8 * sizeof(uint16_t)];
	struct sctp_reset_streams *rs = (struct sctp_reset_streams *)buf;

	memset(buf, 0, sizeof(buf));
	rs->srs_flags = SCTP_STREAM_RESET_INCOMING |
			SCTP_STREAM_RESET_OUTGOING;
	rs->srs_number_streams = nstreams;
	for (uint16_t i = 0; i < nstreams && list; i++)
		rs->srs_stream_list[i] = list[i];

	if (setsockopt(fd, SOL_SCTP_, SCTP_RESET_STREAMS, buf, optlen) < 0)
		printf("  %-46s len=%2zu -> %s\n", label, optlen, strerror(errno));
	else
		printf("  %-46s len=%2zu -> ok\n", label, optlen);
}

static void probe_reset_streams(void)
{
	int cli, srv;
	uint32_t v;
	uint16_t one[1] = { 0 };

	printf("=== SCTP_RESET_STREAMS, extension NOT negotiated ===\n");
	if (pair_up(&cli, &srv, 0) < 0) {
		perror("pair_up");
		return;
	}
	reset_streams("all streams, bare struct", cli, 0, NULL,
		      sizeof(struct sctp_reset_streams));
	close(cli);
	close(srv);

	printf("=== SCTP_RESET_STREAMS, extension negotiated on both ends ===\n");
	if (pair_up(&cli, &srv, 1) < 0) {
		perror("pair_up");
		return;
	}
	if (get_av(cli, SCTP_RECONFIG_SUPPORTED, &v) == 0)
		printf("  reconfig negotiated = %u\n", v);
	if (get_av(cli, SCTP_ENABLE_STREAM_RESET, &v) == 0)
		printf("  stream reset mask   = 0x%x\n", v);

	/* The length is the variable here. sizeof(struct sctp_reset_streams) is
	 * 8 with the flexible array contributing nothing, so try the plausible
	 * candidates rather than guessing which one the kernel wants. */
	reset_streams("all streams, bare struct", cli, 0, NULL,
		      sizeof(struct sctp_reset_streams));
	reset_streams("all streams, struct + one u16 of slack", cli, 0, NULL,
		      sizeof(struct sctp_reset_streams) + sizeof(uint16_t));
	reset_streams("one stream, struct + its list entry", cli, 1, one,
		      sizeof(struct sctp_reset_streams) + sizeof(uint16_t));
	reset_streams("one stream, length excludes the list", cli, 1, one,
		      sizeof(struct sctp_reset_streams));

	printf("  -- after sending on stream 0 --\n");
	warm_stream(cli, 0);
	reset_streams("all streams, bare struct", cli, 0, NULL,
		      sizeof(struct sctp_reset_streams));
	reset_streams("one stream, struct + its list entry", cli, 1, one,
		      sizeof(struct sctp_reset_streams) + sizeof(uint16_t));

	/* Flags in isolation: maybe only one direction is permitted at a time. */
	{
		unsigned char b[sizeof(struct sctp_reset_streams)];
		struct sctp_reset_streams *rs = (struct sctp_reset_streams *)b;
		const struct { const char *n; uint16_t f; } cases[] = {
			{ "INCOMING only", SCTP_STREAM_RESET_INCOMING },
			{ "OUTGOING only", SCTP_STREAM_RESET_OUTGOING },
			{ "no flags", 0 },
		};
		for (unsigned i = 0; i < 3; i++) {
			memset(b, 0, sizeof(b));
			rs->srs_flags = cases[i].f;
			rs->srs_number_streams = 0;
			if (setsockopt(cli, SOL_SCTP_, SCTP_RESET_STREAMS, b,
				       sizeof(b)) < 0)
				printf("  flags %-40s -> %s\n", cases[i].n,
				       strerror(errno));
			else
				printf("  flags %-40s -> ok\n", cases[i].n);
		}
	}

	/* SCTP_RESET_ASSOC takes a bare assoc id, so it is the simpler sibling
	 * and worth measuring in the same breath. */
	{
		sctp_assoc_t id = 0;
		if (setsockopt(cli, SOL_SCTP_, SCTP_RESET_ASSOC, &id,
			       sizeof(id)) < 0)
			printf("  SCTP_RESET_ASSOC -> %s\n", strerror(errno));
		else
			printf("  SCTP_RESET_ASSOC -> ok\n");
	}

	close(cli);
	close(srv);
}

static void auth_key(const char *label, int fd, uint16_t keynumber,
		     uint16_t keylength, size_t payload, size_t optlen)
{
	unsigned char *buf = calloc(1, sizeof(struct sctp_authkey) + payload + 16);
	struct sctp_authkey *k = (struct sctp_authkey *)buf;

	k->sca_keynumber = keynumber;
	k->sca_keylength = keylength;
	memset(k->sca_key, 'k', payload);

	if (setsockopt(fd, SOL_SCTP_, SCTP_AUTH_KEY, buf, optlen) < 0)
		printf("  %-44s len=%3zu -> %s\n", label, optlen, strerror(errno));
	else
		printf("  %-44s len=%3zu -> ok\n", label, optlen);
	free(buf);
}

static void probe_auth_key(void)
{
	int cli, srv;

	printf("=== SCTP_AUTH_KEY (needs net.sctp.auth_enable=1) ===\n");
	if (pair_up(&cli, &srv, 0) < 0) {
		perror("pair_up");
		return;
	}
	printf("  sizeof(struct sctp_authkey) = %zu\n",
	       sizeof(struct sctp_authkey));

	auth_key("key 1, 8 bytes, exact length", cli, 1, 8, 8,
		 sizeof(struct sctp_authkey) + 8);
	/* Does keylength have to agree with the option length? If a too-large
	 * keylength is accepted the kernel would read past the option. */
	auth_key("keylength 200 but only 8 bytes present", cli, 2, 200, 8,
		 sizeof(struct sctp_authkey) + 8);
	auth_key("keylength 4 with 8 bytes present", cli, 3, 4, 8,
		 sizeof(struct sctp_authkey) + 8);
	auth_key("zero-length key (deactivates?)", cli, 4, 0, 0,
		 sizeof(struct sctp_authkey));
	/* Key number 0 is the null key every association starts with. */
	auth_key("key number 0", cli, 0, 8, 8,
		 sizeof(struct sctp_authkey) + 8);

	/* Find the largest key the kernel will take, so the Go side can document
	 * a real bound rather than an invented one. */
	{
		size_t lo = 1, hi = 8192, best = 0;
		while (lo <= hi) {
			size_t mid = (lo + hi) / 2;
			unsigned char *buf =
				calloc(1, sizeof(struct sctp_authkey) + mid);
			struct sctp_authkey *k = (struct sctp_authkey *)buf;
			k->sca_keynumber = 9;
			k->sca_keylength = (uint16_t)mid;
			memset(k->sca_key, 'k', mid);
			if (setsockopt(cli, SOL_SCTP_, SCTP_AUTH_KEY, buf,
				       sizeof(struct sctp_authkey) + mid) == 0) {
				best = mid;
				lo = mid + 1;
			} else {
				hi = mid - 1;
			}
			free(buf);
		}
		printf("  largest accepted key length = %zu\n", best);
	}

	/* SCTP_AUTH_DELETE_KEY and DEACTIVATE_KEY take sctp_authkeyid; check
	 * which key numbers they will act on. */
	{
		struct sctp_authkeyid ak;
		memset(&ak, 0, sizeof(ak));
		ak.scact_keynumber = 1;
		if (setsockopt(cli, SOL_SCTP_, SCTP_AUTH_DEACTIVATE_KEY, &ak,
			       sizeof(ak)) < 0)
			printf("  DEACTIVATE_KEY(1) -> %s\n", strerror(errno));
		else
			printf("  DEACTIVATE_KEY(1) -> ok\n");

		memset(&ak, 0, sizeof(ak));
		ak.scact_keynumber = 1;
		if (setsockopt(cli, SOL_SCTP_, SCTP_AUTH_DELETE_KEY, &ak,
			       sizeof(ak)) < 0)
			printf("  DELETE_KEY(1) after deactivate -> %s\n",
			       strerror(errno));
		else
			printf("  DELETE_KEY(1) after deactivate -> ok\n");
	}

	/* SCTP_AUTH_CHUNK is set-only and RFC 4895 s6.1 says it must precede the
	 * association. Test both sides of that. */
	{
		struct sctp_authchunk ac;
		int fresh = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
		printf("  sizeof(struct sctp_authchunk) = %zu\n", sizeof(ac));
		memset(&ac, 0, sizeof(ac));
		ac.sauth_chunk = 0; /* DATA */
		if (setsockopt(fresh, SOL_SCTP_, SCTP_AUTH_CHUNK, &ac,
			       sizeof(ac)) < 0)
			printf("  AUTH_CHUNK on fresh socket -> %s\n",
			       strerror(errno));
		else
			printf("  AUTH_CHUNK on fresh socket -> ok\n");
		if (setsockopt(cli, SOL_SCTP_, SCTP_AUTH_CHUNK, &ac,
			       sizeof(ac)) < 0)
			printf("  AUTH_CHUNK on connected socket -> %s\n",
			       strerror(errno));
		else
			printf("  AUTH_CHUNK on connected socket -> ok\n");
		close(fresh);
	}

	/* SCTP_HMAC_IDENT is settable as well as readable; the list is ordered
	 * by preference per RFC 4895 s6.2. */
	{
		unsigned char b[sizeof(struct sctp_hmacalgo) + 2 * sizeof(uint16_t)];
		struct sctp_hmacalgo *ha = (struct sctp_hmacalgo *)b;
		memset(b, 0, sizeof(b));
		ha->shmac_num_idents = 1;
		ha->shmac_idents[0] = SCTP_AUTH_HMAC_ID_SHA1;
		if (setsockopt(cli, SOL_SCTP_, SCTP_HMAC_IDENT, b,
			       sizeof(struct sctp_hmacalgo) + sizeof(uint16_t)) < 0)
			printf("  HMAC_IDENT set [SHA1] -> %s\n", strerror(errno));
		else
			printf("  HMAC_IDENT set [SHA1] -> ok\n");

		memset(b, 0, sizeof(b));
		ha->shmac_num_idents = 1;
		ha->shmac_idents[0] = 2; /* unassigned in the IANA registry */
		if (setsockopt(cli, SOL_SCTP_, SCTP_HMAC_IDENT, b,
			       sizeof(struct sctp_hmacalgo) + sizeof(uint16_t)) < 0)
			printf("  HMAC_IDENT set [2, unassigned] -> %s\n",
			       strerror(errno));
		else
			printf("  HMAC_IDENT set [2, unassigned] -> ACCEPTED\n");
	}

	close(cli);
	close(srv);
}

/* The send-side cmsg types. SCTPWrite still uses the deprecated SCTP_SNDRCV, so
 * what matters is whether SCTP_SNDINFO is accepted as its replacement and
 * whether SCTP_PRINFO can ride alongside it in the same sendmsg. */
static void probe_sndinfo_cmsg(void)
{
	int cli, srv;
	char payload[] = "cmsg";
	struct iovec iov = { .iov_base = payload, .iov_len = sizeof(payload) - 1 };

	printf("=== send-side cmsg types ===\n");
	printf("  sizeof(sctp_sndinfo)=%zu sizeof(sctp_prinfo)=%zu "
	       "sizeof(sctp_authinfo)=%zu\n",
	       sizeof(struct sctp_sndinfo), sizeof(struct sctp_prinfo),
	       sizeof(struct sctp_authinfo));
	printf("  cmsg values: SNDRCV=%d SNDINFO=%d RCVINFO=%d NXTINFO=%d "
	       "PRINFO=%d AUTHINFO=%d\n",
	       SCTP_SNDRCV, SCTP_SNDINFO, SCTP_RCVINFO, SCTP_NXTINFO,
	       SCTP_PRINFO, SCTP_AUTHINFO);

	if (pair_up(&cli, &srv, 0) < 0) {
		perror("pair_up");
		return;
	}

	/* SCTP_SNDINFO alone. */
	{
		char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
		struct msghdr m;
		struct cmsghdr *c;
		struct sctp_sndinfo *si;

		memset(&m, 0, sizeof(m));
		memset(cbuf, 0, sizeof(cbuf));
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_control = cbuf;
		m.msg_controllen = sizeof(cbuf);
		c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = IPPROTO_SCTP;
		c->cmsg_type = SCTP_SNDINFO;
		c->cmsg_len = CMSG_LEN(sizeof(*si));
		si = (struct sctp_sndinfo *)CMSG_DATA(c);
		si->snd_sid = 2;
		si->snd_ppid = htonl(0x1234);
		if (sendmsg(cli, &m, 0) < 0)
			printf("  sendmsg with SCTP_SNDINFO -> %s\n",
			       strerror(errno));
		else
			printf("  sendmsg with SCTP_SNDINFO -> ok\n");
	}

	/* SCTP_SNDINFO plus SCTP_PRINFO in one sendmsg: the combination a
	 * partial-reliability send needs. */
	{
		char cbuf[CMSG_SPACE(sizeof(struct sctp_sndinfo)) +
			  CMSG_SPACE(sizeof(struct sctp_prinfo))];
		struct msghdr m;
		struct cmsghdr *c;
		struct sctp_sndinfo *si;
		struct sctp_prinfo *pi;

		memset(&m, 0, sizeof(m));
		memset(cbuf, 0, sizeof(cbuf));
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_control = cbuf;
		m.msg_controllen = sizeof(cbuf);

		c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = IPPROTO_SCTP;
		c->cmsg_type = SCTP_SNDINFO;
		c->cmsg_len = CMSG_LEN(sizeof(*si));
		si = (struct sctp_sndinfo *)CMSG_DATA(c);
		si->snd_sid = 1;

		c = CMSG_NXTHDR(&m, c);
		c->cmsg_level = IPPROTO_SCTP;
		c->cmsg_type = SCTP_PRINFO;
		c->cmsg_len = CMSG_LEN(sizeof(*pi));
		pi = (struct sctp_prinfo *)CMSG_DATA(c);
		pi->pr_policy = SCTP_PR_SCTP_TTL;
		pi->pr_value = 1000;

		if (sendmsg(cli, &m, 0) < 0)
			printf("  sendmsg with SNDINFO+PRINFO -> %s\n",
			       strerror(errno));
		else
			printf("  sendmsg with SNDINFO+PRINFO -> ok\n");
	}

	/* Both SNDRCV and SNDINFO at once: does the kernel refuse, or silently
	 * prefer one? This decides whether a Go send path may emit both during a
	 * migration. */
	{
		char cbuf[CMSG_SPACE(sizeof(struct sctp_sndrcvinfo)) +
			  CMSG_SPACE(sizeof(struct sctp_sndinfo))];
		struct msghdr m;
		struct cmsghdr *c;

		memset(&m, 0, sizeof(m));
		memset(cbuf, 0, sizeof(cbuf));
		m.msg_iov = &iov;
		m.msg_iovlen = 1;
		m.msg_control = cbuf;
		m.msg_controllen = sizeof(cbuf);

		c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = IPPROTO_SCTP;
		c->cmsg_type = SCTP_SNDRCV;
		c->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndrcvinfo));
		((struct sctp_sndrcvinfo *)CMSG_DATA(c))->sinfo_stream = 3;

		c = CMSG_NXTHDR(&m, c);
		c->cmsg_level = IPPROTO_SCTP;
		c->cmsg_type = SCTP_SNDINFO;
		c->cmsg_len = CMSG_LEN(sizeof(struct sctp_sndinfo));
		((struct sctp_sndinfo *)CMSG_DATA(c))->snd_sid = 4;

		if (sendmsg(cli, &m, 0) < 0)
			printf("  sendmsg with SNDRCV+SNDINFO -> %s\n",
			       strerror(errno));
		else
			printf("  sendmsg with SNDRCV+SNDINFO -> ACCEPTED\n");
	}

	close(cli);
	close(srv);
}

int main(void)
{
	probe_reset_streams();
	printf("\n");
	probe_auth_key();
	printf("\n");
	probe_sndinfo_cmsg();
	return 0;
}
