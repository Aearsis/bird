/*
 *  BIRD -- PIM protocol, variant BIDIR-PIM
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_PIM_H_
#define _BIRD_PIM_H_

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "conf/conf.h"
#include "lib/socket.h"
#include "lib/hash.h"
#include "nest/locks.h"
#include "filter/filter.h"

/***************
  Configuration
 ***************/

struct pim_grp_config
{
  node n;				/* member of pim_config->grp_list */
  net_addr ga;				/* multicast group address prefix */
  ip_addr rpa;				/* rendezvous point address */
};

struct pim_iface_config
{
  struct iface_patt i;			/* member of pim_config->patt_list */

  uint election_robustness;

  btime hello_int;			/* hello period */
  btime hello_dly;			/* intial hello delay */
  btime hello_holdtime;			/* hello holdtime transmitted to neighbors */

  btime jp_periodic;			/* join/prune period (t_periodic) */
  btime jp_holdtime;			/* holdtime in upstream joins (should be 3.5 * jp_periodic) */
  btime override_interval;		/* join/prune override interval */
};

struct pim_config
{
  struct proto_config c;
  u8 use_ipv6;

  list grp_list;			/* list of group configs (struct pim_grp_config) */
  list patt_list;			/* list of ifaces (struct pim_iface_config) */

  struct pim_iface_config default_iface_cf;
};

/***************
     Runtime
 ***************/

struct pim_grp_rpa
{
  struct fib_node n;			/* member of pim_proto->groups */
  net_addr px;				/* when a group matches this prefix... */
  ip_addr rpa;				/* .. it is assigned RPA. */
};

struct pim_iface
{
  node n;				/* member of pim_proto->iface_list */
  struct pim_proto *proto;
  struct iface *iface;
  struct pim_iface_config *cf;
  list neigh_list;			/* list of neighbors on this iface (struct pim_neigh) */

  struct object_lock *lock;

  u32 gen_id;				/* generation ID sent in hello messages */
  sock *sk;

  uint pkt_len;				/* length of a packet being constructed in tx buffer */
  int group_count_offset;		/* number of groups while constructing tx join/prune packet (relative to tx buf) */

  timer *hello_timer;			/* periodic hello timer */
  u8 hello_sent;			/* assert sending hello before any join */

  list grp_list;			/* list of pim_grp_iface to be freed along with this */
};

struct pim_metric
{
    u32 pref, metric;
};

#define PIM_METRIC_INFTY ((struct pim_metric){ .pref = -1U, .metric = -1U })

struct pim_rp
{
  node n;				/* member of pim_proto->rp_list */
  struct pim_rp *next;			/* member of pim_proto->rp_hash */
  struct pim_proto *proto;

  ip_addr rpa;
  struct pim_metric rp_metric;		/* my metric towards RPA */

  struct pim_rp_iface *upstream;	/* RPI towards RPA */

  list iface_list;			/* iface specific states (list of pim_rp_iface) */
  list groups;				/* groups having this RPA (for route updates) */
};

struct pim_rp_iface
{
  node n;				/* member of pim_rp->iface_list */
  struct pim_rp_iface *next;		/* member of pim_proto->rpi_states */
  struct pim_rp *rp;
  struct pim_iface *iface;

  /* Designated Forwarder */
  struct pim_neigh *df;
  struct pim_metric df_metric;
  node df_node;				/* member of pim_neigh->df_list */

  /* DF election */
  u8 election_state;			/* PIM_DF_* */
  timer *election_timer;		/* timer used in election */
  u8 mc;				/* message count - different meaning in every state */

  /* Best offer stored in the Backoff state */
  struct pim_neigh *bo;
  struct pim_metric bo_metric;
  node bo_node;				/* member of pim_neigh->bo_list */
};

struct pim_grp
{
  node n;				/* member of pim_rp->groups */
  struct pim_grp *next;			/* member of pim_proto->groups */
  struct pim_proto *proto;

  ip_addr ga;				/* group address */
  ip_addr rpa;				/* Rendezvous Point address */
  struct pim_rp *rp;			/* RP state, if RPA is not zero */

  timer *jt;				/* Upstream Join timer */

  list joined;				/* list of joined ifaces (by any means) - pim_joined_iface */
  list iface_list;			/* list of ifaces joined by PIM - pim_grp_iface */
};

struct pim_joined_iface
{
  node n;				/* member of pim_grp->joined */
  struct iface *iface;
};

struct pim_grp_iface
{
  node n;				/* member of pim_grp->iface_list */
  node iface_node;			/* member of pim_iface->grp_list */
  struct pim_iface *iface;
  struct pim_grp *grp;

  /* Managed by join/prune part */
  timer *et;				/* join expiry timer */
  timer *ppt;				/* prune pending timer */
};

struct pim_neigh
{
    node n;				/* member of pim_iface->neigh_list */
    neighbor *neigh;
    struct pim_iface *iface;

    timer *hold;			/* neighbor liveness timer */
    u32 gen_id;				/* neighbor's Gen ID */

    u8 flags;				/* combination of PIM_NEIGH_* */

    list df_list;			/* RPIs where this neighbor is the acting DF */
    list bo_list;			/* RPIs where this neighbor has the best offer on Backoff state */
};

struct pim_proto
{
  struct proto p;
  struct pim_config *cf;

  u8 use_ipv6;

  struct channel *mrib_channel;		/* MRIB unicast routing topology - read only */
  struct channel *mreq_channel;		/* Table of requests group address -> interface */
  struct channel *mroute_channel;	/* Table of multicast routes */

  struct fib groups;			/* configured group prefixes (struct pim_grp_rpa) */
  list iface_list;			/* list of managed ifaces (struct pim_iface) */

  HASH(struct pim_grp) grp_states;	/* active groups */
  HASH(struct pim_rp) rp_states;	/* known RPs */
  HASH(struct pim_rp_iface) rpi_states;	/* States for (RP, iface) */

  struct f_trie *rp_trie;		/* trie of RPA that we need to take care about (used to filter route updates) */

  event *rpf_update;			/* optimal path to some RPA changed */
};

/* Default values for pim_iface */
#define PIM_DEFAULT_ELECTION_ROBUSTNESS     3
#define PIM_DEFAULT_HELLO_INT          (30 S)
#define PIM_DEFAULT_HELLO_DLY           (5 S)
#define PIM_DEFAULT_HELLO_HOLDTIME    (105 S)
#define PIM_DEFAULT_OVERRIDE_INTERVAL   (3 S)
#define PIM_DEFAULT_JP_PERIODIC        (60 S)

/* Some constants defined in RFC 4601 */
#define PIM_PROTO                         103
#define PIM_HOLDTIME_DEF                  105
#define PIM_HOLDTIME_INF               0xffff
#define PIM_OFFER_PERIOD             (100 MS)
#define PIM_BACKOFF_PERIOD              (1 S)

/* Neigh flags (pim_neigh->flags) */
#define PIM_NF_NEW                       0x01
#define PIM_NF_UP                        0x02
#define PIM_NF_BIDIR                     0x04

/* Hello option types - in host order */
#define PIM_HLO_OPT_HOLDTIME                1
#define PIM_HLO_OPT_GENID                  20
#define PIM_HLO_OPT_BIDIR_CAPABLE          22

/* IANA Adress Family Numbers */
#define PIM_AFN_IP4                         1
#define PIM_AFN_IP6                         2

#define pim_is_ipv6(p) ((p)->use_ipv6)

/***********
   Packets
 ***********/

struct pim_df_msg
{
  u8 type;				/* One of PIM_DF_* */
  ip_addr rpa;

  struct pim_neigh *sender;
  struct pim_metric metric;

  ip_addr target;			/* New Winner in Pass msg, Offering in Backoff */
  struct pim_metric target_metric;
  btime backoff_interval;
};

/* Constants used by both DF packet type and DF state */
#define PIM_DF_OFFER	1
#define PIM_DF_WINNER	2
#define PIM_DF_BACKOFF	3
#define PIM_DF_PASS	4
#define PIM_DF_LOSE	PIM_DF_PASS

#define RPI_IS_DF(rpi) (rpi->election_state & 2)

struct pim_jp_src
{
    net_addr addr;
    u8 flags;
};

#define PIM_JP_RPT          1
#define PIM_JP_WILDCARD     2
#define PIM_JP_SPARSE       4

struct pim_jp_grp			/* Used while decoding jp packets */
{
    net_addr ga;
    u16 j_count, p_count;
    struct pim_jp_src *j, *p;
    u8 flags;
};

#define PIM_JP_BIDIR      128

struct pim_jp_msg
{
    ip_addr target;
    u8 num_groups;
    btime holdtime;
};

/* packets.c */
int pim_sk_open(struct pim_iface *ifa);
int pim_send_hello(struct pim_iface *ifa, uint holdtime);
int pim_send_df(struct pim_rp_iface *rpi, struct pim_df_msg *msg);
int pim_send_upstream_jp(struct pim_grp *grp);
int pim_tx_jp(struct pim_iface *pif, ip_addr *target, struct pim_grp *grp, int join);

/* df.c */
void pim_df_message(struct pim_rp_iface *rpi, struct pim_df_msg *msg);
void pim_df_timer_expired(timer* t);
void pim_df_reelect(struct pim_rp_iface *rpi);
void pim_df_metric_changed(struct pim_rp_iface *rpi, struct pim_metric old_metric);

/* pim.c */
struct pim_grp *pim_grp_find(struct pim_proto *p, ip_addr *ga);
struct pim_iface *pim_iface_find(struct pim_proto *p, struct iface *ifa);

struct pim_rp *pim_rp_find(struct pim_proto *p, ip_addr *rpa);
struct pim_rp * pim_rp_get(struct pim_proto *p, ip_addr *rpa);
void pim_rp_update_routing(struct pim_rp *rp);

struct pim_neigh *pim_neigh_from_neighbor(struct neighbor *n);
struct pim_neigh *pim_neigh_find(struct pim_proto *p, ip_addr *a, struct pim_iface *ifa);
struct pim_neigh *pim_neigh_get(struct pim_proto *p, ip_addr *a, struct pim_iface *ifa);

int pim_send_jp(struct pim_iface *pif, struct pim_grp *grp, int join);
int pim_send_jp_all(struct pim_rp *rp, struct pim_neigh *target, int join);
void pim_jp_upstream_notify(struct pim_grp *grp);
void pim_jp_received(struct pim_proto *p, struct pim_jp_msg *msg, struct pim_jp_grp *grp, struct pim_neigh *n);
void pim_neigh_update(struct pim_neigh *n);
void pim_df_accept(struct pim_iface *ifa, struct pim_df_msg *msg);
void pim_upstream_neighbor_change(struct pim_rp *rp, struct pim_neigh *old, struct pim_neigh *new);
void pim_need_hello(struct pim_iface *ifa);

void pim_config_init(struct pim_config *);
void pim_config_finish(struct pim_config *);
void pim_iface_config_init(struct pim_iface_config *);
void pim_iface_config_finish(struct pim_iface_config *);

int pim_metric_better(struct pim_metric *new, struct pim_metric *old, ip_addr *new_addr, ip_addr *old_addr);
struct pim_metric pim_get_metric(struct pim_rp_iface *rpi);

#endif
