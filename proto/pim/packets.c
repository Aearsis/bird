/*
 *  BIRD -- PIM protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "pim.h"
#include "lib/checksum.h"
#include "lib/ip.h"
#include "lib/resource.h"

struct pim_pkt {
  u8 vers_type;
  u8 subtype_rsvd;
  u16 checksum;
};

struct pim_hello_option {
    u16 opt_type;
    u16 opt_len;
    union {
	u16 holdtime;
	u32 gen_id;
    };
};

struct pim_jp_group {
    u16 joined, pruned;
};

#define PKT_HEADER_SIZE 4
#define DROP(msg, args...) do { log(L_WARN msg, ## args); return 1; } while(0)

#define PKT_HELLO	    0
#define PKT_JOIN_PRUNE	    3
#define PKT_DF             10

#ifndef PARSER
#define IFA_TRACE(flags, msg, args...) \
  do { if (ifa->proto->p.debug & flags) log(L_TRACE "%s: " msg, ifa->proto->p.name , ## args ); } while(0)
#endif

/*
 * Encoded-Unicast Address decoding
 */
static byte *
pim_decode_unicast(byte *buf, ip_addr *addr)
{
  byte af_type = *buf++;
  byte af_encoding = *buf++;
  if (af_encoding != 0)
    return NULL;

  switch (af_type)
    {
      case PIM_AFN_IP4:
	*addr = ipa_from_ip4(get_ip4(buf));
	return buf + 4;
      case PIM_AFN_IP6:
	*addr = ipa_from_ip6(get_ip6(buf));
	return buf + 16;
      default:
	return NULL;
    }
}

static byte *
pim_decode_metric(byte *bbuf, struct pim_metric *metric)
{
  u32 *buf = (u32*) bbuf;
  metric->pref = htonl(*buf++);
  metric->metric = htonl(*buf++);
  return (byte *) buf;
}

/*
 * Encoded-Group Address decoding
 */
static byte *
pim_decode_group(byte *buf, struct pim_jp_grp *grp)
{
  byte af_type = *buf++;
  byte af_encoding = *buf++;
  grp->flags = *buf++;
  if (af_encoding != 0)
    return NULL;
  if (af_type == PIM_AFN_IP4)
  {
    u8 pxlen = *buf++;
    ip4_addr prefix = get_ip4(buf);
    net_fill_ip4(&grp->ga, prefix, pxlen);
    return buf + 4;
  }
  if (af_type == PIM_AFN_IP6)
  {
    u8 pxlen = *buf++;
    ip6_addr prefix = get_ip6(buf);
    net_fill_ip6(&grp->ga, prefix, pxlen);
    return buf + 16;
  }
  return NULL;
}

/*
 * Encoded-Source address decoding
 */
static byte *
pim_decode_source(byte *buf, struct pim_jp_src *src)
{
  byte af_type = *buf++;
  byte af_encoding = *buf++;
  src->flags = *buf++;
  if (af_encoding != 0)
    return NULL;
  if (af_type == PIM_AFN_IP4)
  {
    u8 pxlen = *buf++;
    ip4_addr prefix = get_ip4(buf);
    net_fill_ip4(&src->addr, prefix, pxlen);
    return buf + 4;
  }
  if (af_type == PIM_AFN_IP6)
  {
    u8 pxlen = *buf++;
    ip6_addr prefix = get_ip6(buf);
    net_fill_ip6(&src->addr, prefix, pxlen);
    return buf + 16;
  }
  return NULL;
}

static char *df_types[] = { "BUG", "OFFER", "WINNER", "BACKOFF", "PASS" };

static int
pim_rx_df(struct pim_proto *p, struct pim_pkt *pkt, int len, struct pim_neigh *n)
{
  struct pim_df_msg msg;
  msg.sender = n;
  msg.type = pkt->subtype_rsvd >> 4;

  ASSERT(msg.type <= 4);

  if (!n)
    DROP("Unknown neighbor!");

  n->flags |= PIM_NF_BIDIR; // Otherwise he wouldn't be sending DF messages

  byte *buf = (void *) pkt + PKT_HEADER_SIZE;

  if ((buf = pim_decode_unicast(buf, &msg.rpa)) == NULL)
    DROP("Unknown address type and encoding");

  if ((buf = pim_decode_metric(buf, &msg.metric)) == NULL)
    goto drop;

  TRACE(D_EVENTS, "Received DF %s on %s, RPA %I, metric (%d, %d, %I)",
      df_types[msg.type], n->iface->iface->name, msg.rpa,
      msg.metric.pref, msg.metric.metric, n->neigh->addr);

  if (msg.type >= PIM_DF_BACKOFF)
    {
      buf = pim_decode_unicast(buf, &msg.target);
      buf = pim_decode_metric(buf, &msg.target_metric);

      TRACE(D_PACKETS, "\t arg addr %I", msg.target);
      TRACE(D_PACKETS, "\t arg metric (%lu, %lu)", msg.target_metric.pref, msg.target_metric.metric);
    }

  if (msg.type == PIM_DF_BACKOFF)
    {
      msg.backoff_interval = ntohs(*((u16 *) buf)) MS;
      TRACE(D_PACKETS, "\t backoff period %u ms", msg.backoff_interval TO_MS);
      buf += 2;
    }

  ASSERT(buf == (void *) pkt + len);

  pim_df_accept(n->iface, &msg);
  return 1;

drop:
  return 1;
}

static int
pim_rx_hello(struct pim_proto *p, struct pim_pkt *pkt, int len, struct pim_neigh *n)
{
  u32 gen_id;
  uint holdtime;

  TRACE(D_PACKETS, "Received HELLO from %I", n->neigh->addr);

  struct pim_hello_option *opt = (void *) pkt + PKT_HEADER_SIZE;
  struct pim_hello_option *end = (void *) pkt + len;
  for (; opt < end; opt = (void *) opt + ntohs(opt->opt_len) + 4)
    {
      switch (ntohs(opt->opt_type))
	{
	  case PIM_HLO_OPT_HOLDTIME:
	    holdtime = ntohs(opt->holdtime);
	    if (holdtime == PIM_HOLDTIME_INF)
	      tm_stop(n->hold);
	    else
	      tm_start(n->hold, holdtime);
	    break;
	  case PIM_HLO_OPT_GENID:
	    gen_id = ntohl(opt->gen_id);
	    if (n->gen_id != gen_id)
	      {
		TRACE(D_EVENTS, "Neighbor %I changed generation ID", n->neigh->addr);
		n->flags |= PIM_NF_NEW;
	      }
	    n->gen_id = gen_id;
	    break;
	  case PIM_HLO_OPT_BIDIR_CAPABLE:
	    n->flags |= PIM_NF_BIDIR;
	    break;
	}
    }

  n->flags |= PIM_NF_UP;
  pim_neigh_update(n);

  return 1;
}

#define JP_DROP(msg, args...) do { log(L_WARN msg, ## args); goto drop; } while (0)

static int
pim_rx_jp(struct pim_proto *p, struct pim_pkt *pkt, int len, struct pim_neigh *n)
{
  struct pim_jp_msg msg;

  pool *jp_pool = rp_new(p->p.pool, "Join/Prune RX packet (temporary)");

  byte *buf = (byte *) pkt + 4;
  buf = pim_decode_unicast(buf, &msg.target);
  if (!buf)
    JP_DROP("Unkown address format in target.");

  buf++; // Reserved bytes
  msg.num_groups = *buf++;
  msg.holdtime = ntohs(*((u16 *) buf)) S;
  buf += 2;

  struct pim_jp_grp *groups = mb_alloc(jp_pool, sizeof(struct pim_jp_grp) * msg.num_groups);
  struct pim_jp_grp *grp;
  for (grp = groups; grp < groups + msg.num_groups; grp++)
  {
    buf = pim_decode_group(buf, grp);
    if (!buf)
      JP_DROP("Unknown address format in group address.");
    grp->j_count = ntohs(*(u16 *) buf);
    buf += 2;
    grp->p_count = ntohs(*(u16 *) buf);
    buf += 2;
    u32 count = (grp->j_count + grp->p_count);
    struct pim_jp_src *src = mb_alloc(jp_pool, sizeof(struct pim_jp_src) * count);
    grp->j = src;
    grp->p = src + grp->j_count;
    struct pim_jp_src *end = src + count;
    for (; src != end; src++)
    {
      buf = pim_decode_source(buf, src);
      if (!buf)
	JP_DROP("Invalid source specified");
    }
  }

  if (buf - (byte *) pkt != len)
    JP_DROP("Unexpected packet length (off by %i)", buf - (byte *) pkt - len);

  for (u8 i = 0; i < msg.num_groups; i++)
    pim_jp_received(p, &msg, &groups[i], n);

drop:
  rfree(jp_pool);
  return 1;
}

/*
 * Align the packet to a multiple of 4.
 */
static uint
pkt_pad(struct pim_pkt* pkt, uint len)
{
  uint aligned_len = BIRD_ALIGN(len, 4);
  bzero(((void *) pkt) + len, aligned_len - len);
  return aligned_len;
}

static int
pim_rx_hook(sock *sk, int len)
{
  struct pim_pkt *pkt = (struct pim_pkt *) sk_rx_buffer(sk, &len);
  struct pim_iface *ifa = (struct pim_iface *) sk->data;
  struct pim_proto *p = ifa->proto;

  if (len < 4)
    DROP("Packet too short (%d bytes).", len);

  if ((pkt->vers_type >> 4) != 2)
    DROP("Not a PIMv2 packet (vers %x).", pkt->vers_type >> 4);

  if (!pim_is_ipv6(p))
    {
      int aligned_len = pkt_pad(pkt, len);
      if (!ipsum_verify(pkt, aligned_len, NULL))
	DROP("Bad checksum.");
    }

  struct pim_neigh * n = pim_neigh_get(p, &sk->faddr, ifa);

  switch (pkt->vers_type & 0xf)
    {
      case PKT_HELLO: /* Hello packet */
	return pim_rx_hello(p, pkt, len, n);
      case PKT_JOIN_PRUNE: /* Join/Prune */
	return pim_rx_jp(p, pkt, len, n);
      case PKT_DF: /* DF election */
	return pim_rx_df(p, pkt, len, n);
      default:
	DROP("Packet type %d not implemented!", pkt->vers_type & 0xf);
    }

  return 1;
}

static void
pim_err_hook(sock *sk, int err)
{
  struct pim_iface *ifa = (struct pim_iface *) (sk->data);
  struct pim_proto *p = ifa->proto;
  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->iface->name, err);
}

static inline void *
iface_tx_pkt(struct pim_iface *ifa)
{
  return (void *) ifa->sk->tbuf;
}

static inline void *
iface_tx_buf(struct pim_iface *ifa)
{
  return (void *) ifa->sk->tbuf + ifa->pkt_len;
}

static inline struct pim_hello_option *
iface_tx_hello_option(struct pim_iface *ifa, int opt_len)
{
  struct pim_hello_option * opt = iface_tx_buf(ifa);
  ifa->pkt_len += 4 + opt_len;
  opt->opt_len = htons(opt_len);
  return opt;
}

/*
 * The packet is constructed in the buffer, continually adding another sections.
 * Start by calling pkt_init, then use some encodes, and finish with pkt_send.
 */
static inline struct pim_pkt *
pkt_init(struct pim_iface *ifa, u8 type)
{
  struct pim_pkt *pkt = iface_tx_pkt(ifa);
  pkt->vers_type = (2 << 4) | (type & 0x0f);
  pkt->subtype_rsvd = 0;
  ifa->pkt_len = PKT_HEADER_SIZE;
  return pkt;
}

static inline void
pkt_checksum(struct pim_iface *ifa)
{
  if (pim_is_ipv6(ifa->proto))
    return;

  struct pim_pkt *pkt = iface_tx_pkt(ifa);
  uint aligned_len = pkt_pad(pkt, ifa->pkt_len);
  pkt->checksum = 0;
  pkt->checksum = ipsum_calculate(pkt, aligned_len, NULL);
}

static int
pkt_send(struct pim_iface *ifa)
{
  pkt_checksum(ifa);
  return sk_send(ifa->sk, ifa->pkt_len);
}

/*
 * Send a PIM hello to an interface.
 */
int
pim_send_hello(struct pim_iface *ifa, uint holdtime)
{
  IFA_TRACE(D_PACKETS, "Send HELLO to iface %s", ifa->iface->name);
  pkt_init(ifa, PKT_HELLO);

  struct pim_hello_option *opt = iface_tx_hello_option(ifa, 2);
  opt->opt_type = htons(PIM_HLO_OPT_HOLDTIME);
  opt->holdtime = htons(holdtime);

  opt = iface_tx_hello_option(ifa, 4);
  opt->opt_type = htons(PIM_HLO_OPT_GENID);
  opt->gen_id = htonl(ifa->gen_id);

  opt = iface_tx_hello_option(ifa, 0);
  opt->opt_type = htons(PIM_HLO_OPT_BIDIR_CAPABLE);

  ifa->hello_sent = 1;

  return pkt_send(ifa);
}

/*
 * Encoded-Unicast address
 */
static inline void
pim_encode_unicast(struct pim_iface *ifa, ip_addr *addr)
{
  byte *buf = iface_tx_buf(ifa);
  *buf++ = ipa_is_ip4(*addr) ? PIM_AFN_IP4 : PIM_AFN_IP6;
  *buf++ = 0;
  ifa->pkt_len += 2;
  if (ipa_is_ip4(*addr))
    {
      buf = put_ip4(buf, ipa_to_ip4(*addr));
      ifa->pkt_len += 4;
    }
  else
    {
      buf = put_ip6(buf, ipa_to_ip6(*addr));
      ifa->pkt_len += 16;
    }
}

/*
 * Encoded-Group address
 */
static inline void
pim_encode_group(struct pim_iface *ifa, ip_addr *addr, u8 flags)
{
  u8 *buf = iface_tx_buf(ifa);
  *buf++ = ipa_is_ip4(*addr) ? PIM_AFN_IP4 : PIM_AFN_IP6;
  *buf++ = 0;
  *buf++ = flags;
  if (ipa_is_ip4(*addr))
    {
      *buf++ = IP4_MAX_PREFIX_LENGTH;
      buf = put_ip4(buf, ipa_to_ip4(*addr));
      ifa->pkt_len += 8;
    }
  else
    {
      *buf++ = IP6_MAX_PREFIX_LENGTH;
      buf = put_ip6(buf, ipa_to_ip6(*addr));
      ifa->pkt_len += 20;
    }
}

/*
 * Encoded-Source address
 */
static void
pim_encode_source(struct pim_iface *ifa, ip_addr *prefix, u8 flags)
{
  pim_encode_group(ifa, prefix, flags & 7);
}

static inline void
pim_encode_metric(struct pim_iface *ifa, struct pim_metric *metric)
{
  u32 *buf = iface_tx_buf(ifa);
  *buf++ = htonl(metric->pref);
  *buf++ = htonl(metric->metric);
  ifa->pkt_len += 8;
}

/*
 * Send any DF message to any interface with respect to a RP.
 */
int
pim_send_df(struct pim_rp_iface *rpi, struct pim_df_msg *msg)
{
  struct pim_iface *ifa = rpi->iface;
  IFA_TRACE(D_EVENTS, "Send DF %s to iface %s, RPA %I, metric (%d, %d, %I)",
      df_types[msg->type], ifa->iface->name, msg->rpa,
      msg->metric.pref, msg->metric.metric, ifa->iface->addr->ip);

  struct pim_pkt *pkt = pkt_init(ifa, PKT_DF);
  pkt->subtype_rsvd = msg->type << 4;

  pim_encode_unicast(ifa, &msg->rpa);
  pim_encode_metric(ifa, &msg->metric);

  /* Backoff and Pass messages have a target */
  if (msg->type >= PIM_DF_BACKOFF)
    {
      pim_encode_unicast(ifa, &msg->target);
      pim_encode_metric(ifa, &msg->target_metric);
      if (msg->type == PIM_DF_BACKOFF)
	{
	  u16 *buf = iface_tx_buf(ifa);
	  *buf = htons(msg->backoff_interval TO_MS);
	  ifa->pkt_len += 2;
	}
    }
  return pkt_send(ifa);
}

/*
 * Construct a header for a Join/Prune message
 */
static struct pim_pkt *
pim_jp_header(struct pim_iface *ifa, ip_addr *up_addr, u16 holdtime)
{
  struct pim_pkt *pkt = pkt_init(ifa, 3);
  pim_encode_unicast(ifa, up_addr);
  u16 *buf = iface_tx_buf(ifa);
  *buf++ = 0; // reserved + group count
  *buf++ = htons(holdtime);
  ifa->group_count_offset = ifa->pkt_len + 1;
  ifa->pkt_len += 4;
  return pkt;
}

/*
 * Add a group to a packet being constructed
 */
static struct pim_jp_group *
pim_jp_group(struct pim_iface *ifa, struct pim_grp *grp)
{
  char *pkt = iface_tx_pkt(ifa);
  pkt[ifa->group_count_offset]++;

  pim_encode_group(ifa, &grp->ga, PIM_JP_BIDIR);

  struct pim_jp_group *group = iface_tx_buf(ifa);
  group->joined = 0;
  group->pruned = 0;
  ifa->pkt_len += 4;

  return group;
}

/*
 * Add a wildcard source joined/pruned for a group.
 */
void
pim_jp_wildcard(struct pim_iface *ifa, struct pim_jp_group *group, ip_addr *rpa, int join)
{
  if (join && group->pruned)
    bug("Tried to join source after pruning one (while constructing tx join/prune packet)");

  pim_encode_source(ifa, rpa, PIM_JP_WILDCARD | PIM_JP_RPT);

  if (join)
    group->joined = htons(ntohs(group->joined) + 1);
  else
    group->pruned = htons(ntohs(group->pruned) + 1);
}

/*
 * For a specified RP, send a Join/Prune for all groups to a target.
 * Used when the DF changes.
 */
int
pim_send_jp_all(struct pim_rp *rp, struct pim_neigh *target, int join)
{
  struct pim_proto *p = rp->proto;
  TRACE(D_PACKETS, "Sending all %s for RP %I:", join ? "joins" : "prunes", rp->rpa);

  struct pim_iface *pif = target->iface;
  pim_need_hello(pif);

  pim_jp_header(pif, &target->neigh->addr, pif->cf->jp_holdtime TO_S);

  struct pim_grp *grp;
  WALK_LIST(grp, rp->groups)
    {
      struct pim_jp_group *group = pim_jp_group(pif, grp);
      pim_jp_wildcard(pif, group, &rp->rpa, join);
      TRACE(D_PACKETS, "\t%I", grp->ga);
    }

  return pkt_send(pif);
}

/*
 * Send a Join/Prune package on an interface to a target.
 * Is used even for sending packets targeted to ourselves.
 */
int
pim_tx_jp(struct pim_iface *pif, ip_addr *target, struct pim_grp *grp, int join)
{
  struct pim_proto *p = grp->proto;
  TRACE(D_PACKETS, "Sending %s(*, %I) to %I, holdtime %u",
      join ? "Join" : "Prune", grp->ga, *target,
      pif->cf->jp_holdtime TO_S);

  pim_jp_header(pif, target, pif->cf->jp_holdtime TO_S);
  struct pim_jp_group *group = pim_jp_group(pif, grp);
  pim_jp_wildcard(pif, group, &grp->rpa, join);
  return pkt_send(pif);
}

int
pim_sk_open(struct pim_iface *ifa)
{
  sock *sk = sk_new(ifa->proto->p.pool);
  sk->type = SK_IP;
  sk->dport = PIM_PROTO;
  sk->saddr = ifa->iface->addr->ip;
  sk->iface = ifa->iface;

  sk->data = ifa;
  sk->daddr = pim_is_ipv6(ifa->proto) ? IP6_PIM_ROUTERS : IP4_PIM_ROUTERS;
  sk->ttl = 1;
  sk->rx_hook = pim_rx_hook;
  sk->err_hook = pim_err_hook;

  sk_set_tbsize(sk, 1024);
  sk_set_rbsize(sk, 1024);

  if (pim_is_ipv6(ifa->proto))
    if (sk_set_ipv6_checksum(sk, 16) < 0)
      goto err;

  if (sk_open(sk) < 0)
    goto err;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_join_group(sk, sk->daddr) < 0)
    goto err;

  ifa->sk = sk;
  return 1;
err:
  log(L_ERR "%s: Socket error: %s%#m", ifa->proto->p.name, sk->err);
  rfree(sk);
  return 0;
}
