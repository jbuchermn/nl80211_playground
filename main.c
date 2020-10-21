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

    /* Name and index of physical device */
    uint32_t wiphy_idx;
    char wiphy_name[30];

    /* Name and index of interface of type monitor */
    uint32_t if_index;
    char if_name[30];
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
    printf("...done\n");
    return 0;
}
