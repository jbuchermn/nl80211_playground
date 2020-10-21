#include <errno.h>
#include <linux/nl80211.h> //NL80211 definitions

#include <netlink/genl/ctrl.h> //genl_ctrl_resolve
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h> //genl_connect, genlmsg_put
#include <netlink/netlink.h>   //lots of netlink functions

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile int running = 1;
void ctrl_c_handler(int _) { running = 0; }

struct netlink_client {
    int id;
    struct nl_sock *socket;
    struct nl_cb *cb;
    int cb_in_prog;

    /* Name of physical device */
    int wiphy_idx;
    char wiphy_name[30];
    /* Name of interface of type monitor */
    char if_name[30];
};

static int callback_finish(struct nl_msg *msg, void *arg) {
    struct netlink_client *nl = arg;

    nl->cb_in_prog = 0;
    return NL_OK;
}

static int callback_get_wiphy(struct nl_msg *msg, void *arg) {
    struct netlink_client *nl = arg;
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
        strcpy(nl->wiphy_name, "");
        nl->wiphy_idx=-1;
        if (tb_msg[NL80211_ATTR_WIPHY_NAME]) {
            strcpy(nl->wiphy_name,
                   nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));
        }
        if (tb_msg[NL80211_ATTR_WIPHY]) {
            nl->wiphy_idx = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
        }
        printf("Found device that supports monitor mode: %i / %s\n",
               nl->wiphy_idx, nl->wiphy_name);
    }

    return NL_OK;
}

static int callback_new_interface(struct nl_msg *msg, void *arg) {
    struct netlink_client *nl = arg;
    nl_msg_dump(msg, stdout);

    struct genlmsghdr *genlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
    nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(genlh, 0),
              genlmsg_attrlen(genlh, 0), NULL);

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

    nl_cb_set(nl->cb, NL_CB_FINISH, NL_CB_CUSTOM, callback_finish, nl);
    nl_cb_set(nl->cb, NL_CB_ACK, NL_CB_CUSTOM, callback_finish, nl);
    nl_cb_err(nl->cb, NL_CB_VERBOSE, NULL, stderr);

    return 0;
}

static void netlink_client_destroy(struct netlink_client *nl) {
    nl_cb_put(nl->cb);
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
}

int main(int argc, char **argv) {
    struct netlink_client nl;

    /* signal(SIGINT, ctrl_c_handler); */

    if (netlink_client_init(&nl)) {
        fprintf(stderr, "Error initializing netlink 802.11\n");
        return -1;
    }

    /* Look for device with monitor mode */
    {
        nl_cb_set(nl.cb, NL_CB_VALID, NL_CB_CUSTOM, callback_get_wiphy, &nl);
        struct nl_msg *msg = nlmsg_alloc();
        if (!msg) {
            fprintf(stderr, "Failed to allocate netlink message.\n");
            return -2;
        }

        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl.id, 0, NLM_F_DUMP,
                    NL80211_CMD_GET_WIPHY, 0);
        nl_send_auto_complete(nl.socket, msg);

        nl.cb_in_prog = 1;
        while (nl.cb_in_prog) {
            nl_recvmsgs(nl.socket, nl.cb);
        }
        nlmsg_free(msg);
    }

    /* TODO: Break if no device */
    strcpy(nl.if_name, "mon0");

    /* create monitor interface */
    {
        nl_cb_set(nl.cb, NL_CB_VALID, NL_CB_CUSTOM, callback_new_interface,
                  &nl);
        struct nl_msg *msg = nlmsg_alloc();
        if (!msg) {
            fprintf(stderr, "Failed to allocate netlink message.\n");
            return -2;
        }

        genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl.id, 0, NLM_F_DUMP,
                    NL80211_CMD_NEW_INTERFACE, 0);

        nla_put_u32(msg, NL80211_ATTR_WIPHY, nl.wiphy_idx);
        nla_put_string(msg, NL80211_ATTR_IFNAME, nl.if_name);
        nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);


        nl_msg_dump(msg, stderr);

        nl_send_auto_complete(nl.socket, msg);

        nl.cb_in_prog = 1;
        while (nl.cb_in_prog) {
            nl_recvmsgs(nl.socket, nl.cb);
        }
        nlmsg_free(msg);
    }

    printf("Exiting...\n");
    netlink_client_destroy(&nl);
    printf("...done\n");
    return 0;
}
