#include <errno.h>
#include <linux/if.h>
#include <linux/nl80211.h>
#include <sys/ioctl.h>

#include "radiotap-library/platform.h"
#include "radiotap-library/radiotap_iter.h"

#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>
#include <pcap/pcap.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* #define _SEND_ */

static volatile int running = 1;
void ctrl_c_handler(int _) { running = 0; }

struct netlink_client {
    int id;
    struct nl_sock *socket;
    struct nl_cb *cb;

    /* Name and index of physical device */
    uint32_t wiphy_idx;
    char wiphy_name[10];

    /* Name and index of interface of type monitor */
    uint32_t if_index;
    char if_name[10];
};

struct netlink_client_command {
    struct netlink_client *root;

    int cb_in_progress;
    struct nl_msg *msg;

    void *ret;
};

static int callback_finish(struct nl_msg *msg, void *arg) {
    struct netlink_client_command *cmd = arg;

    cmd->cb_in_progress = 0;
    return NL_OK;
}

static int callback_get_wiphy(struct nl_msg *msg, void *arg) {
    struct netlink_client_command *cmd = arg;
    /* nl_msg_dump(msg, stdout); */

    struct genlmsghdr *genlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(genlh, 0),
              genlmsg_attrlen(genlh, 0), NULL);

    int supports_monitor_mode = 0;
    if (tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES]) {

        int rem_mode;
        struct nlattr *nl_mode;
        nla_for_each_nested(nl_mode, tb_msg[NL80211_ATTR_SUPPORTED_IFTYPES],
                            rem_mode) {
            if (nla_type(nl_mode) == NL80211_IFTYPE_MONITOR)
                supports_monitor_mode = 1;
        }
    }
    if (supports_monitor_mode) {
        if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
            strcpy(cmd->root->wiphy_name,
                   nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
        }
        if (tb_msg[NL80211_ATTR_WIPHY]) {
            cmd->root->wiphy_idx = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        }
        printf("Found device that supports monitor mode: %i / %s\n",
               cmd->root->wiphy_idx, cmd->root->wiphy_name);
    }

    return NL_OK;
}

static int callback_get_interface(struct nl_msg *msg, void *arg) {
    struct netlink_client_command *cmd = arg;
    /* nl_msg_dump(msg, stdout); */

    struct genlmsghdr *genlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(genlh, 0),
              genlmsg_attrlen(genlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_IFNAME]) {
        if (!strcmp(cmd->root->if_name,
                    nla_get_string(tb_msg[NL80211_ATTR_IFNAME]))) {
            *((int *)(cmd->ret)) = 1;
            if (tb_msg[NL80211_ATTR_IFINDEX]) {
                cmd->root->if_index = nla_get_u32(tb_msg[NL80211_ATTR_IFINDEX]);
            }
        }
    }

    return NL_OK;
}

static int callback_new_interface(struct nl_msg *msg, void *arg) {
    struct netlink_client_command *cmd = arg;
    /* nl_msg_dump(msg, stdout); */

    struct genlmsghdr *genlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(genlh, 0),
              genlmsg_attrlen(genlh, 0), NULL);

    if (tb_msg[NL80211_ATTR_IFINDEX]) {
        cmd->root->if_index = nla_get_u32(tb_msg[NL80211_ATTR_IFNAME]);
    }
    return NL_OK;
}

static int callback_set_mode(struct nl_msg *msg, void *arg) {
    struct netlink_client_command *cmd = arg;
    nl_msg_dump(msg, stdout);

    return NL_OK;
}

static int netlink_client_init(struct netlink_client *nl) {
    nl->socket = nl_socket_alloc();
    if (!nl->socket) {
        fprintf(stderr, "Failed to allocate netlink socket.\n");
        return -ENOMEM;
    }

    nl_socket_set_buffer_size(nl->socket, 8192, 8192);

    if (genl_connect(nl->socket)) {
        fprintf(stderr, "Failed to connect to netlink socket.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOLINK;
    }

    nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
    if (nl->id < 0) {
        fprintf(stderr, "nl80211 interface not found.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOENT;
    }

    nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!nl->cb) {
        fprintf(stderr, "Failed to allocate netlink callback.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOMEM;
    }

    nl_cb_err(nl->cb, NL_CB_VERBOSE, NULL, stderr);

    return 0;
}

static void netlink_client_destroy(struct netlink_client *nl) {
    nl_cb_put(nl->cb);
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
}

static int netlink_client_command_init(struct netlink_client_command *command,
                                       struct netlink_client *root, int cmd,
                                       int flags,
                                       nl_recvmsg_msg_cb_t callback) {
    command->root = root;
    command->ret = 0;

    nl_cb_set(root->cb, NL_CB_FINISH, NL_CB_CUSTOM, callback_finish, command);
    nl_cb_set(root->cb, NL_CB_ACK, NL_CB_CUSTOM, callback_finish, command);
    nl_cb_set(root->cb, NL_CB_VALID, NL_CB_CUSTOM, callback, command);

    command->msg = nlmsg_alloc();
    if (!command->msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        return -2;
    }
    genlmsg_put(command->msg, NL_AUTO_PORT, NL_AUTO_SEQ, root->id, 0, flags,
                cmd, 0);
    return 0;
}

static int netlink_client_command_run(struct netlink_client_command *command) {
    nl_send_auto_complete(command->root->socket, command->msg);
    command->cb_in_progress = 1;
    while (command->cb_in_progress) {
        nl_recvmsgs(command->root->socket, command->root->cb);
    }
    nlmsg_free(command->msg);

    return 0;
}

static uint8_t tx_radiotap_header[] __attribute__((unused)) = {
    0x00, // it_version
    0x00, // it_pad

    0x0d, 0x00, // it_len

    // it_present
    // bits 7-0, 15-8, 23-16, 31-24
    // set CHANNEL: bit 3
    // set TX_FLAGS: bit 15
    // set MCS: bit 19
    0x08, 0x80, 0x08, 0x00,

    // CHANNEL
    // u16 frequency (MHz), u16 flags
    // frequency: to be set
    // flags 7-0, 15-8
    // set Dynamic CCK-OFDM channel: bit 10
    // set 2GHz channel: bit 7
    0x00, 0x00, 0x80, 0x04,

    // TX_FLAGS
    // u16 flags 7-0, 15-8
    // set NO_ACK: bit 3
    0x08, 0x00,

    // MCS
    // u8 known, u8 flags, u8 mcs
    // known: Guard Interval, Bandwidth, MCS, STBC, FEC
    // flags: _xx1_gbb, xx: STBC, g: GI, bb: bandwidth
    (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW |
     IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC |
     IEEE80211_RADIOTAP_MCS_HAVE_FEC),
    0x10, 0x00};

static uint8_t tx_ieee80211_header[] __attribute__((unused)) = {
    0x88, 0x41, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x13, 0x22,
    0x33, 0x44, 0x55, 0x66, 0x13, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00};

int main(int argc, char **argv) {
    struct netlink_client nl;
    struct netlink_client_command cmd;

    /* signal(SIGINT, ctrl_c_handler); */

    if (netlink_client_init(&nl)) {
        fprintf(stderr, "Error initializing netlink 802.11\n");
        return -1;
    }

    /* look for monitor-capable devices */
    netlink_client_command_init(&cmd, &nl, NL80211_CMD_GET_WIPHY, NLM_F_DUMP,
                                callback_get_wiphy);
    netlink_client_command_run(&cmd);

    /* TODO: Pick device */
    /* strcpy(nl.wiphy_name, "phy3"); */
    /* nl.wiphy_idx = 3; */
    strcpy(nl.if_name, "monrs0");

    /* see if interface exists already */
    netlink_client_command_init(&cmd, &nl, NL80211_CMD_GET_INTERFACE,
                                NLM_F_DUMP, callback_get_interface);
    int exists;
    cmd.ret = &exists;
    netlink_client_command_run(&cmd);
    if (!exists) {
        printf("Interface '%s' does not yet exist, creating it...\n",
               nl.if_name);
        /* create monitor interface */
        netlink_client_command_init(&cmd, &nl, NL80211_CMD_NEW_INTERFACE, 0,
                                    callback_new_interface);
        nla_put_u32(cmd.msg, NL80211_ATTR_WIPHY, nl.wiphy_idx);
        nla_put_string(cmd.msg, NL80211_ATTR_IFNAME, nl.if_name);
        nla_put_u32(cmd.msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
        netlink_client_command_run(&cmd);

        printf("...done\n");
    } else {
        printf("Interface '%s' exists, putting it in monitor mode...\n",
               nl.if_name);

        netlink_client_command_init(&cmd, &nl, NL80211_CMD_SET_INTERFACE, 0,
                                    callback_set_mode);
        nla_put_u32(cmd.msg, NL80211_ATTR_IFINDEX, nl.if_index);
        nla_put_u32(cmd.msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
        netlink_client_command_run(&cmd);
        printf("...done\n");
    }

    netlink_client_destroy(&nl);

    int err;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_create(nl.if_name, errbuf);
    pcap_set_snaplen(pcap, -1);
    pcap_set_timeout(pcap, -1);

    /*
     * ip link set ifname up
     */
    struct ifreq ifr;
    int fd;

    strncpy(ifr.ifr_name, nl.if_name, IFNAMSIZ);
    fd = socket(PF_PACKET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("Could not open up socket\n");
    }

    err = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (err) {
        printf("Error: SIOCGIFFLAGS\n");
        close(fd);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP;
    err = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (err)
        perror("SIOCSIFFLAGS");
    close(fd);

    /* activate pcap */
    if ((err = pcap_activate(pcap)) != 0) {
        printf("PCAP activate failed: %d %d\n", err, PCAP_ERROR_IFACE_NOT_UP);
    } else if (pcap_setnonblock(pcap, 1, errbuf) != 0) {
        printf("PCAP setnonblock failed: %s\n", errbuf);
    }

#ifdef _SEND_
    uint8_t tx_buf[4096];
    uint8_t *tx_ptr = tx_buf;
    int tx_len = 4096;

    memcpy(tx_ptr, tx_radiotap_header, sizeof(tx_radiotap_header));

    // Set frequency
    /* uint16_t freq = 2447; */
    /* tx_ptr[8] = (uint8_t)freq; */
    /* tx_ptr[9] = (uint8_t)(freq >> 8); */

    // Set MCS
    // https://en.wikipedia.org/wiki/IEEE_802.11n-2009#Data_rates
    /* tx_ptr[15] |= IEEE80211_RADIOTAP_MCS_BW_40; */
    /* tx_ptr[15] |= IEEE80211_RADIOTAP_MCS_SGI; */
    /* tx_ptr[16] = 0; */

    tx_ptr += sizeof(tx_radiotap_header);
    tx_len -= sizeof(tx_radiotap_header);

    memcpy(tx_ptr, tx_ieee80211_header, sizeof(tx_ieee80211_header));
    tx_ptr += sizeof(tx_ieee80211_header);
    tx_len -= sizeof(tx_ieee80211_header);

    for (; tx_ptr - tx_buf < 256; tx_ptr++)
        *tx_ptr = 0xDD;

    for (;;) {
        if (pcap_inject(pcap, tx_buf, tx_ptr - tx_buf) == tx_ptr - tx_buf) {
            printf(".");
        }
    }
#else
    for (;;) {
        struct pcap_pkthdr header;
        const uint8_t *radiotap_header = pcap_next(pcap, &header);
        if (radiotap_header) {
            struct ieee80211_radiotap_iterator it;
            int status = ieee80211_radiotap_iterator_init(
                &it, (struct ieee80211_radiotap_header *)radiotap_header,
                header.caplen, NULL);

            int flags = -1;
            int mcs_known = -1;
            int mcs_flags = -1;
            int mcs = -1;
            int rate = -1;
            int chan = -1;
            int chan_flags = -1;
            int antenna = -1;

            while (status == 0) {
                if ((status = ieee80211_radiotap_iterator_next(&it)))
                    continue;

                switch (it.this_arg_index) {
                case IEEE80211_RADIOTAP_FLAGS:
                    flags = *(uint8_t *)(it.this_arg);
                    break;
                case IEEE80211_RADIOTAP_MCS:
                    mcs_known = *(uint8_t *)(it.this_arg);
                    mcs_flags = *(((uint8_t *)(it.this_arg)) + 1);
                    mcs = *(((uint8_t *)(it.this_arg)) + 2);
                    break;
                case IEEE80211_RADIOTAP_RATE:
                    rate = *(uint8_t *)(it.this_arg);
                    break;
                case IEEE80211_RADIOTAP_CHANNEL:
                    chan = get_unaligned((uint16_t *)(it.this_arg));
                    chan_flags = get_unaligned(((uint16_t *)(it.this_arg)) + 1);
                    break;
                case IEEE80211_RADIOTAP_ANTENNA:
                    antenna = *(uint8_t *)(it.this_arg);
                    break;
                default:
                    break;
                }
            }

            const uint8_t *payload = radiotap_header + it._max_length;
            int payload_len = header.caplen - it._max_length;
            if (flags >= 0 && (((uint8_t)flags) & IEEE80211_RADIOTAP_F_FCS)) {
                payload_len -= 4;
            }

            printf("%d: %02x %02x %02x %02x\n", payload_len, *payload,
                   *(payload + 1), *(payload + 2), *(payload + 3));
        }
    }

#endif

    return 0;
}
