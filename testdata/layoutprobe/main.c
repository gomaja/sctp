// Compare the kernel's struct layouts against what the Go package declares.
#include <stdio.h>
#include <stddef.h>
#include <netinet/sctp.h>
#include <sys/socket.h>

int main(void) {
    printf("sockaddr_storage size=%zu\n", sizeof(struct sockaddr_storage));
    printf("sctp_paddrinfo size=%zu assoc@%zu addr@%zu state@%zu cwnd@%zu srtt@%zu rto@%zu mtu@%zu\n",
        sizeof(struct sctp_paddrinfo),
        offsetof(struct sctp_paddrinfo, spinfo_assoc_id),
        offsetof(struct sctp_paddrinfo, spinfo_address),
        offsetof(struct sctp_paddrinfo, spinfo_state),
        offsetof(struct sctp_paddrinfo, spinfo_cwnd),
        offsetof(struct sctp_paddrinfo, spinfo_srtt),
        offsetof(struct sctp_paddrinfo, spinfo_rto),
        offsetof(struct sctp_paddrinfo, spinfo_mtu));
    printf("sctp_status size=%zu assoc@%zu state@%zu rwnd@%zu unack@%zu pend@%zu in@%zu out@%zu frag@%zu prim@%zu\n",
        sizeof(struct sctp_status),
        offsetof(struct sctp_status, sstat_assoc_id),
        offsetof(struct sctp_status, sstat_state),
        offsetof(struct sctp_status, sstat_rwnd),
        offsetof(struct sctp_status, sstat_unackdata),
        offsetof(struct sctp_status, sstat_penddata),
        offsetof(struct sctp_status, sstat_instrms),
        offsetof(struct sctp_status, sstat_outstrms),
        offsetof(struct sctp_status, sstat_fragmentation_point),
        offsetof(struct sctp_status, sstat_primary));
    printf("sctp_rtoinfo size=%zu  sctp_assocparams size=%zu  sctp_initmsg size=%zu\n",
        sizeof(struct sctp_rtoinfo), sizeof(struct sctp_assocparams),
        sizeof(struct sctp_initmsg));
    printf("sctp_assoc_value size=%zu  sctp_sndrcvinfo size=%zu  sctp_event_subscribe size=%zu\n",
        sizeof(struct sctp_assoc_value), sizeof(struct sctp_sndrcvinfo),
        sizeof(struct sctp_event_subscribe));
    return 0;
}
