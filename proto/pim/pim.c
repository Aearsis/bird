/*
 *  BIRD -- PIM protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

/*
 * DOC: Protocol Independent Multicast (PIM)
 *
 * This protocol implements Bidirectional PIM, a variant of PIM-SM that builds
 * bidirectional shared trees connecting multicast sources and receivers.
 * Bidirectional trees are built using a fail-safe Designated Forwarder (DF)
 * election mechanism operating on each link of a multicast topology. With
 * the assistance of the DF, multicast data is natively forwarded from sources
 * to the Rendezvous-Point (RP) and hence along the shared tree to receivers
 * without requiring source-specific state.  The DF election takes place at RP
 * discovery time and provides the route to the RP, thus eliminating
 * the requirement for data-driven protocol events.
 *
 * Its implementation is split into three files, |packets.c| handling low-level
 * packet formats and |pim.c| implementing BIRD interface and protocol logic.
 * |df.c| contains code associated with DF election (many cases).
 *
 * We can split the implementation into three logical units. First, the DF
 * logic, ensures there is exactly one DF elected on every interface. Its
 * majority is in the |df.c| source file. Then there is the Join/Prune
 * mechanism, shared with other versions of PIM. It listens for downstream
 * requests, and pushes them to the BIRD's multicast request table. Also, it
 * sends joins upstream when appropriate. Last, there is the forwarding logic.
 * It is fairly simple - whenever there is a request for a group and interface,
 * and we are the DF on that interface, forward the group there.
 */

#include <linux/rtnetlink.h>

#include "pim.h"
#include "filter/filter.h"
#include "lib/ip.h"
#include "lib/event.h"
#include "nest/route.h"

#define HASH_RP_KEY(n)		n->rpa
#define HASH_RP_NEXT(n)		n->next
#define HASH_RP_EQ(a,b)		ipa_equal(a,b)
#define HASH_RP_FN(k)		ip6_hash(k)

#define HASH_GRP_KEY(n)		n->ga
#define HASH_GRP_NEXT(n)	n->next
#define HASH_GRP_EQ(a,b)	ipa_equal(a,b)
#define HASH_GRP_FN(k)		ip6_hash(k)

#define HASH_RPI_KEY(n)			n->rp->rpa, n->iface->iface->index
#define HASH_RPI_NEXT(n)		n->next
#define HASH_RPI_EQ(rpa, ifa, rpb, ifb)	ipa_equal(rpa, rpb) && ifa == ifb
#define HASH_RPI_FN(rpa, ix)		(ip6_hash(rpa) ^ ix)

/******************************************************************************
                                Neighbor management
 ******************************************************************************/

static void
pim_neigh_expired(timer *tm)
{
  struct pim_neigh *n = tm->data;
  n->flags &= ~PIM_NF_UP;
  pim_neigh_update(n);
}

static struct pim_neigh *
pim_neigh_new(struct pim_iface *ifa, neighbor *n)
{
  struct pim_proto *p = ifa->proto;
  struct pim_neigh *pn = mb_allocz(p->p.pool, sizeof(struct pim_neigh));
  TRACE(D_EVENTS, "New neighbor %I", n->addr);
  add_tail(&ifa->neigh_list, NODE pn);

  pn->neigh = n;
  pn->iface = ifa;

  pn->hold = tm_new_set(p->p.pool, pim_neigh_expired, pn, 0, 0);
  pn->flags = PIM_NF_NEW;

  init_list(&pn->df_list);
  init_list(&pn->bo_list);
  tm_start(pn->hold, PIM_HOLDTIME_DEF);
  n->data = pn;
  return pn;
}

struct pim_neigh *
pim_neigh_from_neighbor(neighbor* n)
{
  if (!n)
    return NULL;

  return (struct pim_neigh *) n->data;
}

struct pim_neigh *
pim_neigh_find(struct pim_proto *p, ip_addr *a, struct pim_iface *ifa)
{
  neighbor *n = neigh_find2(&p->p, a, ifa->iface, 0);
  return pim_neigh_from_neighbor(n);
}

struct pim_neigh *
pim_neigh_get(struct pim_proto *p, ip_addr *a, struct pim_iface *ifa)
{
  neighbor *n = neigh_find2(&p->p, a, ifa->iface, 0);
  return pim_neigh_from_neighbor(n) ? : pim_neigh_new(ifa, n);
}

/******************************************************************************
                                RPA state management
 ******************************************************************************/

struct pim_rp_iface *
pim_rp_iface_new(struct pim_rp *rp, struct pim_iface *ifa)
{
  struct pim_proto *p = rp->proto;
  TRACE(D_EVENTS, "New RP iface state (%I, %s)", rp->rpa, ifa->iface->name);
  struct pim_rp_iface *rpi = mb_allocz(rp->proto->p.pool, sizeof(struct pim_rp_iface));
  rpi->rp = rp;
  rpi->iface = ifa;

  HASH_INSERT(rp->proto->rpi_states, HASH_RPI, rpi);
  add_tail(&rp->iface_list, NODE rpi);

  rpi->df = NULL;
  rpi->df_metric = PIM_METRIC_INFTY;

  rpi->election_state = PIM_DF_OFFER;
  rpi->election_timer = tm_new_set(rp->proto->p.pool, pim_df_timer_expired, rpi, 0, 0);

  pim_df_reelect(rpi);

  return rpi;
}

void
pim_rp_iface_free(struct pim_rp_iface *rpi)
{
  struct pim_rp *rp = rpi->rp;
  struct pim_proto *p = rp->proto;

  if (rpi == rp->upstream)
    {
      rp->upstream = NULL;
      ev_schedule(p->rpf_update);
    }

  rfree(rpi->election_timer);

  HASH_REMOVE(p->rpi_states, HASH_RPI, rpi);
  rem_node(NODE rpi);
  if (NODE_VALID(&rpi->df_node))
    rem_node(&rpi->df_node);
  if (NODE_VALID(&rpi->bo_node))
    rem_node(&rpi->bo_node);
  mb_free(rpi);
}

static inline struct pim_rp_iface *
pim_rp_iface_find2(struct pim_proto *p, ip_addr rpa, unsigned ifindex)
{
  return HASH_FIND(p->rpi_states, HASH_RPI, rpa, ifindex);
}

struct pim_rp_iface *
pim_rp_iface_find(struct pim_rp *rp, struct iface *iface)
{
  return pim_rp_iface_find2(rp->proto, rp->rpa, iface->index);
}

static inline struct pim_rp_iface *
pim_rp_iface_get(struct pim_proto *p, ip_addr rpa, struct iface *iface)
{
  struct pim_rp_iface *rpi;
  if ((rpi = pim_rp_iface_find2(p, rpa, iface->index)))
    return rpi;

  struct pim_iface *ifa = pim_iface_find(p, iface);
  if (!ifa)
    return NULL; /* Cannot get rpi for non-existent iface */

  return pim_rp_iface_new(pim_rp_get(p, &rpa), ifa);
}

/*
 * The DF on upstream link has changed from old to new. If possible, send
 * prunes to the old DF, and joins to the new one.
 */
void
pim_upstream_neighbor_change(struct pim_rp *rp, struct pim_neigh *old, struct pim_neigh *new)
{
  struct pim_proto *p = rp->proto;

  TRACE(D_EVENTS, "Upstream neighbor for %I changed.", rp->rpa);
  if (old) pim_send_jp_all(rp, old, 0);
  if (new)
    {
      pim_send_jp_all(rp, new, 1);

      struct pim_grp *grp;
      WALK_LIST(grp, rp->groups)
	{
	  grp->jt->recurrent = new->iface->cf->jp_periodic TO_S;
	  tm_start(grp->jt, grp->jt->recurrent);
	}
    }

  pim_rp_update_routing(rp);
}

/*
 * Callback which is called from within rt_route. The route rt is the best one
 * for given RP, indicating our upstream and metric.
 */
static void
pim_rp_set_rpf(struct proto *P, void *data, rte* rt)
{
  struct pim_rp *rp = data;
  struct pim_proto *p = (struct pim_proto *) P;
  TRACE(D_EVENTS, "Setting RPF on %I to %s", rp->rpa, rt->attrs->iface->name);

  struct pim_rp_iface *old_upstream = rp->upstream;
  struct pim_metric old_metric = rp->rp_metric;

  if (!old_upstream || old_upstream->iface->iface != rt->attrs->iface)
    rp->upstream = pim_rp_iface_get(p, rp->rpa, rt->attrs->iface);

  if (rp->upstream == NULL)
    {
      /* When an interface is already deleted in PIM, but not yet in other
       * protocols, routes may still exist. Reschedule the event and try again later.
       */
      ev_schedule(p->rpf_update);
      return;
    }

  rp->rp_metric.pref = rt->pref;
  rp->rp_metric.metric = rt_get_igp_metric(rt);

  if (old_upstream != rp->upstream)
    {
      pim_upstream_neighbor_change(rp,
	old_upstream ? old_upstream->df : NULL,
	rp->upstream ? rp->upstream->df : NULL);
    }

  struct pim_rp_iface *rpi;
  WALK_LIST(rpi, rp->iface_list)
    pim_df_metric_changed(rpi, (rpi == old_upstream)
      ? PIM_METRIC_INFTY : old_metric);
}

/*
 * Ask the MRIB what the interface and metric towards RPA is.
 */
static void
pim_rp_fill_rpf(struct pim_rp *rp)
{
  net_addr n;
  net_fill_ip_host(&n, rp->rpa);
  rt_route(rp->proto->mrib_channel, &n, pim_rp_set_rpf, rp);
}


struct pim_rp *
pim_rp_new(struct pim_proto *p, ip_addr *rpa)
{
  TRACE(D_EVENTS, "New RP state %I", *rpa);
  struct pim_rp *rp = mb_allocz(p->p.pool, sizeof(struct pim_rp));
  rp->rpa = *rpa;
  HASH_INSERT(p->rp_states, HASH_RP, rp);

  net_addr_ip4 net;
  net_fill_ip_host((net_addr *) &net, *rpa);

  trie_add_prefix(p->rp_trie, (net_addr *) &net, 0, net.pxlen);

  rp->proto = p;
  rp->upstream = NULL;
  rp->rp_metric = PIM_METRIC_INFTY;

  init_list(&rp->iface_list);
  init_list(&rp->groups);

  struct pim_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
      pim_rp_iface_new(rp, ifa);

  pim_rp_fill_rpf(rp);

  return rp;
}

struct pim_rp *
pim_rp_find(struct pim_proto *p, ip_addr *rpa)
{
  return HASH_FIND(p->rp_states, HASH_RP, *rpa);
}

struct pim_rp *
pim_rp_get(struct pim_proto *p, ip_addr *rpa)
{
  return pim_rp_find(p, rpa) ? : pim_rp_new(p, rpa);
}

/******************************************************************************
                                Group state management
 ******************************************************************************/

static void pim_request_join(struct pim_grp_iface *grpi, int join);

static void
pim_grp_iface_expire(timer *et)
{
  struct pim_grp_iface *grpi = et->data;
  pim_request_join(grpi, 0);
}

static void
pim_grp_iface_prune_expire(timer *et)
{
  struct pim_grp_iface *grpi = et->data;
  struct pim_proto *p = grpi->grp->proto;
  TRACE(D_EVENTS, "Prune pending time for (%I, %s) expired.", grpi->grp->ga, grpi->iface->iface->name);
  pim_send_jp(grpi->iface, grpi->grp, 0);
  pim_request_join(grpi, 0);
}

static struct pim_grp_iface *
pim_grp_iface_new(struct pim_grp *grp, struct pim_iface *ifa)
{
  struct pim_grp_iface *gi = mb_allocz(grp->proto->p.pool, sizeof(struct pim_grp_iface));
  add_tail(&grp->iface_list, NODE gi);
  add_tail(&ifa->grp_list, &gi->iface_node);
  gi->iface = ifa;
  gi->grp = grp;

  struct pim_proto *p = grp->proto;
  TRACE(D_EVENTS, "New grp_iface (%I, %s)", grp->ga, ifa->iface->name);

  gi->et = tm_new_set(grp->proto->p.pool, pim_grp_iface_expire, gi, 0, 0);
  gi->ppt = tm_new_set(grp->proto->p.pool, pim_grp_iface_prune_expire, gi, 0, 0);
  return gi;
}

struct pim_grp_iface *
pim_grp_iface_find(struct pim_grp *grp, struct pim_iface *ifa)
{
  struct pim_grp_iface *grpi;
  WALK_LIST(grpi, grp->iface_list)
    if (grpi->iface == ifa)
	return grpi;
  return NULL;
}

struct pim_grp_iface *
pim_grp_iface_get(struct pim_grp *grp, struct pim_iface *ifa)
{
  return pim_grp_iface_find(grp, ifa) ? : pim_grp_iface_new(grp, ifa);
}

static void
pim_grp_iface_free(struct pim_grp_iface *grpi)
{
  rfree(grpi->et);
  rfree(grpi->ppt);
  rem_node(NODE grpi);
  rem_node(&grpi->iface_node);
  mb_free(grpi);
}

/*
 * Add/remove the multicast request.
 */
static void
pim_request_join(struct pim_grp_iface *grpi, int join)
{
  struct pim_proto *p = grpi->grp->proto;
  net_addr_union addr;
  net_fill_mreq((net_addr *) &addr, grpi->grp->ga, grpi->iface->iface->index);
  net *n = net_get(p->mreq_channel->table, (net_addr *) &addr);

  if (join)
    {
      rta a0 = {
	.src = p->p.main_source,
	.source = RTS_PIM,
	.dest = RTD_MREQUEST,
	.iface = grpi->iface->iface,
      };
      rta *a = rta_lookup(&a0);
      rte *e = rte_get_temp(a);

      e->net = n;
      rte_update2(p->mreq_channel, (net_addr *) &addr, e, p->p.main_source);
    }
  else
    {
      rte_update2(p->mreq_channel, (net_addr *) &addr, NULL, p->p.main_source);
      pim_grp_iface_free(grpi);
    }
}

static void
pim_grp_free(struct pim_grp *grp)
{
  struct pim_grp_iface *grpi, *grpi_next;
  struct pim_joined_iface *ji, *ji_next;
  WALK_LIST_DELSAFE(grpi, grpi_next, grp->iface_list)
    {
      pim_grp_iface_free(grpi);
    }

  WALK_LIST_DELSAFE(ji, ji_next, grp->joined)
    {
      rem_node(NODE ji);
      mb_free(ji);
    }

  rfree(grp->jt);
  HASH_REMOVE(grp->proto->grp_states, HASH_GRP, grp);
  if (grp->rp)
    rem_node(NODE grp);
  mb_free(grp);
}

static void
pim_grp_upstream_expire(timer *t)
{
  struct pim_grp *grp = t->data;
  pim_send_upstream_jp(grp);
  if (EMPTY_LIST(grp->joined))
    pim_grp_free(grp);
}

struct pim_grp *
pim_grp_find(struct pim_proto *p, ip_addr *ga)
{
  return HASH_FIND(p->grp_states, HASH_GRP, *ga);
}

static ip_addr
pim_grp_find_rpa(struct pim_proto *p, ip_addr *ga)
{
  struct net_addr n;
  struct pim_grp_rpa *gr;

  net_fill_ip_host(&n, *ga);
  gr = fib_route(&p->groups, &n);
  if (gr)
    return gr->rpa;
  return IPA_NONE;
}

static struct pim_grp *
pim_grp_new(struct pim_proto *p, ip_addr *ga)
{
  TRACE(D_EVENTS, "New group state %I", *ga);
  struct pim_grp *grp = mb_allocz(p->p.pool, sizeof(struct pim_grp));
  grp->ga = *ga;
  HASH_INSERT(p->grp_states, HASH_GRP, grp);

  grp->proto = p;
  init_list(&grp->joined);
  init_list(&grp->iface_list);
  grp->rpa = pim_grp_find_rpa(p, ga);
  /* RP may still be unknown. If we are lucky we can find the RPA in a Join
   * packet. */
  if (!ipa_zero(grp->rpa))
    {
      grp->rp = pim_rp_get(p, &grp->rpa);
      add_tail(&grp->rp->groups, NODE grp);
    }
  grp->jt = tm_new_set(p->p.pool, pim_grp_upstream_expire, grp, 0, PIM_DEFAULT_JP_PERIODIC TO_S);

  return grp;
}

struct pim_grp *
pim_grp_get(struct pim_proto *p, ip_addr *ga)
{
  return pim_grp_find(p, ga) ?: pim_grp_new(p, ga);
}

/******************************************************************************
                                Iface management
 ******************************************************************************/

static void
pim_hello_hook(timer *tm)
{
  struct pim_iface *ifa = (struct pim_iface *) tm->data;
  pim_send_hello(ifa, ifa->cf->hello_holdtime TO_S);
}

void
pim_need_hello(struct pim_iface *pif)
{
  if (!pif->hello_sent)
    {
      pim_send_hello(pif, pif->cf->hello_holdtime TO_S);
      tm_start_btime(pif->hello_timer, pif->cf->hello_int);
    }
}

static inline int
pim_iface_is_up(struct pim_iface *ifa)
{
  return !!ifa->sk;
}

static void
pim_iface_add(struct object_lock *lock)
{
  struct pim_iface *ifa  = lock->data;
  struct pim_proto *p = ifa->proto;

  if (pim_iface_is_up(ifa))
    return;

  if (!pim_sk_open(ifa))
    {
      log(L_ERR "Failed opening socket");
      return;
    }

  ifa->hello_timer->randomize = ifa->cf->hello_dly TO_S;
  tm_start(ifa->hello_timer, 0);
  ifa->hello_timer->randomize = 0;

  HASH_WALK(ifa->proto->rp_states, next, rp)
      pim_rp_iface_new(rp, ifa);
  HASH_WALK_END;

  TRACE(D_EVENTS, "Iface %s is UP and RUNNING!", ifa->iface->name);
}

static struct pim_iface *
pim_iface_new(struct pim_proto *p, struct iface *iface, struct pim_iface_config *ic)
{
  TRACE(D_EVENTS, "New iface %s", iface->name);
  struct pim_iface *ifa = mb_allocz(p->p.pool, sizeof(struct pim_iface));
  add_tail(&p->iface_list, NODE ifa);
  ifa->iface = iface;
  ifa->cf = ic;
  ifa->proto = p;
  ifa->gen_id = random_u32();
  init_list(&ifa->neigh_list);
  init_list(&ifa->grp_list);

  ifa->hello_timer = tm_new_set(p->p.pool, pim_hello_hook, ifa, ic->hello_dly TO_S, ic->hello_int TO_S);

  struct object_lock *lock = olock_new(p->p.pool);
  lock->addr = pim_is_ipv6(p) ? IPA_NONE : ipa_from_ip4(net4_prefix(&iface->addr->prefix));
  lock->type = OBJLOCK_IP;
  lock->port = PIM_PROTO;
  lock->inst = ifa->gen_id;
  lock->iface = iface;
  lock->data = ifa;
  lock->hook = pim_iface_add;
  ifa->lock = lock;

  olock_acquire(lock);

  return ifa;
}

static int
pim_iface_down(struct pim_iface *ifa)
{
  if (!pim_iface_is_up(ifa))
    return 0;

  tm_stop(ifa->hello_timer);
  rfree(ifa->sk);
  ifa->sk = NULL;
  return 0;
}

static int
pim_iface_free(struct pim_iface* ifa)
{
  struct pim_proto *p = ifa->proto;
  node *n, *next;

  WALK_LIST_DELSAFE(n, next, ifa->grp_list)
    pim_grp_iface_free(SKIP_BACK(struct pim_grp_iface, iface_node, n));

  HASH_WALK_DELSAFE(p->rp_states, next, rp)
    {
      struct pim_rp_iface *rpi = pim_rp_iface_find(rp, ifa->iface);
      if (rpi)
	pim_rp_iface_free(rpi);
    }
  HASH_WALK_END;

  rem_node(NODE ifa);
  mb_free(ifa);
  return 0;
}

static void
pim_iface_dump(struct pim_iface *ifa)
{
  debug("\tInterface %s, %s, holdtime %u, gen ID %lu\n", ifa->iface->name,
    pim_iface_is_up(ifa) ? "up" : "down", ifa->cf->hello_holdtime TO_S,
    ifa->gen_id);

  struct pim_neigh *n;
  WALK_LIST(n, ifa->neigh_list)
    debug("\t\tNeighbor %I%s%s\n",
      n->neigh->addr,
      (n->flags & PIM_NF_UP) ? " UP" : "",
      (n->flags & PIM_NF_BIDIR) ? " BIDIR" : ""
    );
}

struct pim_iface *
pim_iface_find(struct pim_proto *p, struct iface * ifa)
{
  struct pim_iface * pif;
  WALK_LIST(pif, p->iface_list)
    if (pif->iface == ifa)
      return pif;

  return NULL;
}

struct pim_iface *
pim_iface_find_by_index(struct pim_proto *p, unsigned ifindex)
{
  struct pim_iface * pif;
  WALK_LIST(pif, p->iface_list)
    if (pif->iface->index == ifindex)
      return pif;

  return NULL;
}

void
pim_iface_config_init(struct pim_iface_config * ifc)
{
  init_list(&ifc->i.ipn_list);

  ifc->hello_int = PIM_DEFAULT_HELLO_INT;
  ifc->hello_dly = PIM_DEFAULT_HELLO_DLY;
  ifc->election_robustness = PIM_DEFAULT_ELECTION_ROBUSTNESS;
  ifc->override_interval = PIM_DEFAULT_OVERRIDE_INTERVAL;
  ifc->jp_periodic = PIM_DEFAULT_JP_PERIODIC;
  ifc->hello_holdtime = -1; /* Computed from hello_int in pim_iface_config_finish() */
  ifc->jp_holdtime = -1; /* Computed from periodic */
}

void
pim_config_init(struct pim_config *cf)
{
   init_list(&cf->grp_list);
   init_list(&cf->patt_list);
   pim_iface_config_init(&cf->default_iface_cf);
   pim_iface_config_finish(&cf->default_iface_cf);
}

void
pim_iface_config_finish(struct pim_iface_config * ifc)
{
  if (ifc->hello_holdtime == -1)
    ifc->hello_holdtime = (ifc->hello_int * 4) - (ifc->hello_int / 2); // 3.5 * hello_int
  if (ifc->jp_holdtime == -1)
    ifc->jp_holdtime = (ifc->jp_periodic * 4) - (ifc->jp_periodic / 2);
}

static struct channel_config *
pim_default_channel(struct proto_config *c, uint net_type)
{
  if (NULL == proto_cf_find_channel(c, net_type))
    return channel_config_new(NULL, net_type, c);
  return NULL;
}

void
pim_config_finish(struct pim_config *cf)
{
  struct proto_config *c = &cf->c;
  int v4 = c->net_type != NET_IP6;

  cf->use_ipv6 = !v4;

  // XXX: three times going through a list
  struct channel_config *cc;
  pim_default_channel(c, v4 ? NET_IP4 : NET_IP6);
  if (cc = pim_default_channel(c, v4 ? NET_MREQ4 : NET_MREQ6))
    cc->out_filter = FILTER_ACCEPT;
  pim_default_channel(c, v4 ? NET_MGRP4 : NET_MGRP6);
}

/******************************************************************************
				Others
 ******************************************************************************/

/*
 * Publish a new route for (*,G). Because we do not always have the upstream
 * state (deleting the route), accept an address and RP instead.
 */
static void
pim_rt_update(struct pim_proto *p, ip_addr *ga, struct pim_rp *rp)
{
  net_addr_union addr;
  net_fill_mgrp((net_addr *) &addr, *ga);
  net *n = net_get(p->mroute_channel->table, (net_addr *) &addr);

  if (rp && rp->upstream)
    {
      rta a0 = {
	.src = p->p.main_source,
	.source = RTS_PIM,
	.dest = RTD_MULTICAST,
      };
      rta *a = rta_lookup(&a0);
      rte *e = rte_get_temp(a);

      e->net = n;

      RTE_MGRP_CLRALL(e->u.mkrt.iifs);
      RTE_MGRP_CLRALL(e->u.mkrt.oifs);

      /* If known, forward the group upstream */
      if (rp->upstream)
	{
	  RTE_MGRP_SET(rp->upstream->iface->iface, e->u.mkrt.iifs);
	  RTE_MGRP_SET(rp->upstream->iface->iface, e->u.mkrt.oifs);
	}

      /* Forward from interface iff we are the DF */
      struct pim_rp_iface *rpi;
      WALK_LIST(rpi, rp->iface_list)
	if (RPI_IS_DF(rpi))
	  RTE_MGRP_SET(rpi->iface->iface, e->u.mkrt.iifs);

      /* Forward to interface iff we are the DF and there are requests for it */
      struct pim_grp *grp = pim_grp_find(p, ga);
      struct pim_joined_iface *j;
      if (grp)
	WALK_LIST(j, grp->joined)
	  if (RPI_IS_DF(pim_rp_iface_get(p, rp->rpa, j->iface)))
	    RTE_MGRP_SET(j->iface, e->u.mkrt.oifs);

      /* Force the route to be reloaded in all protocols. */
      /* XXX: This was necessary, but I have forgotten why. */
      rte_update2(p->mroute_channel, (net_addr *) &addr, NULL, p->p.main_source);
      rte_update2(p->mroute_channel, (net_addr *) &addr, e, p->p.main_source);
    }
  else
    {
      rte_update2(p->mroute_channel, (net_addr *) &addr, NULL, p->p.main_source);
    }
}

/*
 * After a change of the RP tree, publish changes to the routing table.
 */
void
pim_rp_update_routing(struct pim_rp *rp)
{
  struct pim_proto *p = rp->proto;
  struct pim_grp *grp;

  WALK_LIST(grp, rp->groups)
    pim_rt_update(p, &grp->ga, rp);
}
/*
 * Send a Join/Prune packet for a group to an interface.
 */
int
pim_send_jp(struct pim_iface *pif, struct pim_grp *grp, int join)
{
  struct pim_proto *p = grp->proto;

  struct pim_rp_iface *rpi = pim_rp_iface_get(p, grp->rpa, pif->iface);

  pim_need_hello(pif);

  ip_addr *target;
  if (RPI_IS_DF(rpi))
    {
      target = &pif->iface->addr->ip; // Prune-Echo
    }
  else
    {
      if (!rpi->df)
	{
	  TRACE(D_PACKETS, "Cannot send %s(*, %I), there is no DF elected on the link.", (join ? "Join" : "Prune"), grp->ga);
	  return 0;
	}
      target = &rpi->df->neigh->addr;
    }

  return pim_tx_jp(pif, target, grp, join);
}

/*
 * Send a Join/Prune packet upstream.
 */
int
pim_send_upstream_jp(struct pim_grp *grp)
{
  struct pim_proto *p = grp->proto;
  int join = !EMPTY_LIST(grp->joined);

  if (!grp->rp || !grp->rp->upstream)
    {
      TRACE(D_PACKETS, "\tCannot send upstream %s(*, %I), we have no upstream yet.", join ? "Join" : "Prune", grp->ga);
      return 0;
    }

  return pim_send_jp(grp->rp->upstream->iface, grp, !EMPTY_LIST(grp->joined));
}

/*
 * Join or Prune a group upstream. Sets up the timers to do it periodically.
 */
void
pim_upstream_join(struct pim_grp *grp)
{
  struct pim_proto *p = grp->proto;
  int join = !EMPTY_LIST(grp->joined);
  int old_join = tm_active(grp->jt);

  if (join == old_join)
    return;

  if (!grp->rp)
    {
      TRACE(D_EVENTS, "Group %I has no RPA assigned, cannot %s.", grp->ga, join ? "join" : "prune");
      return;
    }

  TRACE(D_EVENTS, "%s group %I on upstream", join ? "Joining" : "Leaving", grp->ga);

  struct pim_rp_iface *rpi = grp->rp->upstream;
  if (rpi && rpi->df)
    {
      struct pim_iface *ifa = rpi->iface;
      grp->jt->recurrent = ifa->cf->jp_periodic TO_S;
      tm_start(grp->jt, 0);
    }
  else if (!join)
    {
      pim_grp_free(grp);
    }
}

/*
 * Join or Prune from downstream. Will add the interface into joined list,
 * and Join/Prune the upstream if necessary.
 */
void
pim_downstream_join(struct pim_grp *grp, struct iface *iface, int join)
{
  struct pim_proto *p = grp->proto;
  struct pim_joined_iface *pji, *next;

  struct pim_iface *pif = pim_iface_find(p, iface);
  if (!pif)
    {
      log(L_WARN, "Unknown iface %s mc request for PIM.", iface->name);
      return;
    }

  TRACE(D_EVENTS, "Iface %s %s group %I", iface->name, join ? "joined" : "left", grp->ga);

  if (join)
    {
      pji = mb_allocz(p->p.pool, sizeof(*pji));
      pji->iface = iface;
      add_tail(&grp->joined, NODE pji);
    }
  else
    {
      WALK_LIST_DELSAFE(pji, next, grp->joined)
	if (pji->iface == iface)
	  rem_node(NODE pji);
    }

  pim_upstream_join(grp);
  pim_rt_update(p, &grp->ga, grp->rp);
}

#define DROP(msg, args...) do { log(L_WARN msg, ##args); return; } while (0)

void
pim_jp_received(struct pim_proto *p, struct pim_jp_msg *msg, struct pim_jp_grp *grp, struct pim_neigh *n)
{
  if (grp->flags & PIM_JP_BIDIR == 0)
    TRACE(D_PACKETS, "Group should not be managed by PIM-BIDIR.");

  if (net_pxlen(&grp->ga) == 0)
    bug("Wildcard group JP received, not implemented!");

  if (!net_is_host(&grp->ga))
    DROP("Received group JP notify with nontrivial prefix - not defined in RFC!");

  if (grp->j_count + grp->p_count != 1)
    DROP("Received group BIDIR Join/Prune with %u sources - nonsense!", grp->j_count + grp->p_count);

  struct pim_jp_src *src = grp->j_count ? grp->j : grp->p; // Well, grp->j is always the right pointer, but...

  if (src->flags & PIM_JP_WILDCARD == 0)
    DROP("Not a wildcard source in BIDIR - nonsense!");

  ip_addr prefix = net_prefix(&grp->ga);
  struct pim_grp *grp_state = pim_grp_get(p, &prefix);

  if (!ipa_equal(net_prefix(&src->addr), grp_state->rpa))
  {
    if (ipa_zero(grp_state->rpa))
      {
	grp_state->rpa = net_prefix(&src->addr);
	grp_state->rp = pim_rp_get(p, &grp_state->rpa);
	add_tail(&grp_state->rp->groups, NODE grp_state);
	TRACE(D_PACKETS, "Different RPA in Join/Prune -> ignore!");
      }
    else
      return; // silent drop
  }

  struct pim_neigh *target = pim_neigh_get(p, &msg->target, n->iface);

  if (target->neigh->scope != SCOPE_HOST)
    {
      /* This message is not for us. Just watch it. */
      struct pim_rp_iface *rpi = pim_rp_iface_find2(p, grp_state->rpa, n->iface->iface->index);

      if (rpi->rp->upstream == rpi)
	{
	  TRACE(D_PACKETS, "Received upstream %s for group %I", grp->j_count ? "join" : "prune", grp_state->ga);
	  struct pim_iface_config *cf = rpi->iface->cf;
	  if (tm_active(grp_state->jt))
	    tm_start_btime(grp_state->jt, grp->j_count
	      ? cf->jp_periodic * 1.1 + random_u32() % cf->jp_periodic * 0.3
	      : random_u32() % cf->override_interval * 0.9);
	}
      return;
    }

  struct pim_grp_iface *grpi = pim_grp_iface_get(grp_state, n->iface);

  TRACE(D_PACKETS, "Received downstream %s for group %I", grp->j_count ? "join" : "prune", grp_state->ga);

  if (grp->j_count)
    {
      if (msg->holdtime == PIM_HOLDTIME_INF)
	tm_stop(grpi->et);
      else
	tm_start_btime(grpi->et, msg->holdtime);
      tm_stop(grpi->ppt);

      pim_request_join(grpi, 1);
    }
  else
    tm_start_btime(grpi->ppt, grpi->iface->cf->override_interval);
}

/*
 * Update the pim_neigh structure, either because we got neigh_notify, or
 * because we got a hello / missed a few hellos.
 */
void
pim_neigh_update(struct pim_neigh *pn)
{
  struct pim_proto *p = pn->iface->proto;
  TRACE(D_EVENTS, "Neighbor update %I", pn->neigh->addr);

  if (pn->flags & PIM_NF_NEW)
    {
      TRACE(D_EVENTS, "\tNew neighbor is UP %I", pn->neigh->addr);
      pn->flags &= ~PIM_NF_NEW;
    }

  if (!(pn->flags & PIM_NF_UP))
    {
      TRACE(D_EVENTS, "\tNeighbor is DOWN %I", pn->neigh->addr);
      pn->neigh->data = NULL;
      rem_node(NODE pn);

      node *n, *next;

      WALK_LIST_DELSAFE(n, next, pn->df_list)
	{
	  struct pim_rp_iface *rpi = SKIP_BACK(struct pim_rp_iface, df_node, n);
	  rpi->df = NULL;
	  rpi->df_metric = PIM_METRIC_INFTY;
	  pim_df_reelect(rpi);
	  rem_node(n);
	}
      WALK_LIST_DELSAFE(n, next, pn->bo_list)
	{
	  struct pim_rp_iface *rpi = SKIP_BACK(struct pim_rp_iface, bo_node, n);
	  rpi->bo = NULL;
	  rpi->bo_metric = PIM_METRIC_INFTY;
	  rem_node(n);
	}

      rfree(pn->hold);
      mb_free(pn);
      return;
    }
}

void
pim_neigh_notify(neighbor *n)
{
  if (!n->data) return;

  struct pim_neigh *pn = (struct pim_neigh *) n->data;
  struct pim_proto *p = pn->iface->proto;

  TRACE(D_EVENTS, "Neighbor notify %I", n->addr);

  if (n->scope <= 0)
    pn->flags &= ~PIM_NF_UP;

  pim_neigh_update(pn);
}

int
pim_metric_better(struct pim_metric *new, struct pim_metric *old, ip_addr *new_addr, ip_addr *old_addr)
{
  if (new->pref < old->pref)
    return 1;
  if (new->pref > old->pref)
    return 0;

  if (new->metric < old->metric)
    return 1;
  if (new->metric > old->metric)
    return 0;

  if (new_addr && old_addr)
    if (ipa_compare(*new_addr, *old_addr) <= 0)
      return 1;

  return 0;
}

/*
 * Get the metric to be announced on interface in DF messages.
 * Ensures we always announce infinite metric on upstream.
 */
struct pim_metric
pim_get_metric(struct pim_rp_iface *rpi)
{
  struct pim_rp *rp = rpi->rp;

  if (rp->upstream == rpi)
    return PIM_METRIC_INFTY;

  return rp->rp_metric;
}

void
pim_df_accept(struct pim_iface* ifa, struct pim_df_msg *msg)
{
  struct pim_proto *p = ifa->proto;

  struct pim_rp_iface *rpi = pim_rp_iface_get(p, msg->rpa, ifa->iface);
  pim_df_message(rpi, msg);
}

/*
 * A routing change occured, such that the path to one of our RPAs was changed.
 * Walk through every RP and fill its upstream and metric.
 */
static void
pim_rpf_update(void *P)
{
  struct pim_proto *p = P;
  TRACE(D_EVENTS, "Scheduled RPF interface update running.");
  HASH_WALK(p->rp_states, next, rp)
  {
    pim_rp_fill_rpf(rp);
  }
  HASH_WALK_END;
}

static void
pim_rt_notify(struct proto *P, struct channel *c, net *n, rte *new, rte *old, ea_list *attrs)
{
  struct pim_proto *p = (struct pim_proto *) P;
  struct net_addr *addr = n->n.addr;

  switch (addr->type)
    {
      case NET_IP4:
      case NET_IP6:
	if (!ev_active(p->rpf_update) && trie_match_net(p->rp_trie, addr))
	  /* We have a RP which is affected by this route. Recalculate the RP trees. */
	  ev_schedule(p->rpf_update);
	return;

      case NET_MREQ4:
      case NET_MREQ6:
	/* Because we receive only optimal route updates, we care only about
	 * the first and the last route announced. Having both or none means
	 * nothing changes for us. */
	if ((new == NULL) == (old == NULL))
	  return;

	ip_addr ga = net_prefix(addr);
	struct pim_grp *grp = pim_grp_get(p, &ga);
	struct iface *iface = if_find_by_index(net_ifindex(addr));
	pim_downstream_join(grp, iface, new != NULL);
	return;

      case NET_MGRP4:
      case NET_MGRP6:
      default:
	return;
    }
}

static void
pim_if_notify(struct proto *P, uint flags, struct iface *iface)
{
  struct pim_proto *p = (struct pim_proto *) P;
  struct pim_config *c = (struct pim_config *) P->cf;

  if (iface->flags & IF_IGNORE)
    return;

  if (flags & IF_CHANGE_UP)
    {
      struct pim_iface_config *ic;
      ic = (struct pim_iface_config *) iface_patt_find(&c->patt_list, iface, iface->addr);
      if (!ic)
	  ic = &c->default_iface_cf;
      pim_iface_new(p, iface, ic);
      return;
    }


  if (flags & IF_CHANGE_DOWN)
    {
      struct pim_iface * ifa = pim_iface_find(p, iface);
      pim_iface_down(ifa);
      pim_iface_free(ifa);
    }
}

static int
pim_start(struct proto *P)
{
  struct pim_proto *p = (struct pim_proto *) P;
  TRACE(D_EVENTS, "PIM protocol starting");

  init_list(&p->iface_list);

  HASH_INIT(p->rp_states, P->pool, 8);
  HASH_INIT(p->rpi_states, P->pool, 8);
  HASH_INIT(p->grp_states, P->pool, 8);

  fib_init(&p->groups, P->pool, pim_is_ipv6(p) ? NET_IP6 : NET_IP4,
    sizeof(struct pim_grp), 0, 0, NULL);

  linpool *lp = lp_new(P->pool, sizeof(struct f_trie_node));
  p->rp_trie = f_new_trie(lp, sizeof(struct f_trie_node));

  struct pim_grp_config *grp;
  WALK_LIST(grp, p->cf->grp_list)
  {
    struct pim_grp_rpa *gr = fib_get(&p->groups, &grp->ga);
    gr->px = grp->ga;
    gr->rpa = grp->rpa;
    if (!ipa_equal(grp->rpa, IPA_NONE))
      pim_rp_get(p, &grp->rpa);
  }

  return PS_UP;
}

static int
pim_shutdown(struct proto *P)
{
  struct pim_proto *p = (struct pim_proto *) P;
  struct pim_iface *ifa;
  WALK_LIST_FIRST(ifa, p->iface_list)
  {
    pim_send_hello(ifa, 0);
    pim_iface_down(ifa);
    pim_iface_free(ifa);
  }

  return PS_DOWN;
}

static void
pim_dump(struct proto *P)
{
  static char *dfStates[] = {"BUG", "Offer", "Winner", "Backoff", "Lose"};
  struct pim_proto *p = (struct pim_proto *) P;
  struct pim_iface *ifa;
  WALK_LIST(ifa, p->iface_list)
    pim_iface_dump(ifa);

  HASH_WALK(p->grp_states, next, grp)
    {
      debug("\tGroup %I, RP %I, ", grp->ga, grp->rpa);
      debug("PIM joins:");
      struct pim_grp_iface *grpi;
      WALK_LIST(grpi, grp->iface_list)
	debug(" %s%s", grpi->iface->iface->name, tm_active(grpi->ppt) ? " (prune pending)" : "");
      debug("; joined on:");
      struct pim_joined_iface *ji;
      WALK_LIST(ji, grp->joined)
	  debug(" %s", ji->iface->name);
      debug("\n");
    }
  HASH_WALK_END;

  HASH_WALK(p->rp_states, next, rp)
    {
      debug("\tRP %I, RPF %s\n", rp->rpa, rp->upstream ? rp->upstream->iface->iface->name : "[no upstream]");
      struct pim_rp_iface *rpi;
      WALK_LIST(rpi, rp->iface_list)
	debug("\t\tiface %s, DF state: %s, DF: %I\n", rpi->iface->iface->name, dfStates[rpi->election_state], rpi->df ? rpi->df->neigh->addr : IPA_NONE);
    }
  HASH_WALK_END;
}

int pim_rte_same(rte *e1, rte *e2)
{
  if (e1->attrs->dest == RTD_MULTICAST)
    return RTE_MGRP_SAME(e1->u.mkrt.iifs, e2->u.mkrt.oifs);
  return 1;
}


static struct proto *
pim_init(struct proto_config *c)
{
  struct proto *p = proto_new(c);
  struct pim_proto *pim = (struct pim_proto *) p;
  struct pim_config *pim_c = (struct pim_config *) c;

  pim->use_ipv6 = c->net_type == NET_MGRP6;

  pim->mrib_channel   = proto_add_channel(p, proto_cf_find_channel(c, !pim->use_ipv6 ? NET_IP4   : NET_IP6));
  pim->mreq_channel   = proto_add_channel(p, proto_cf_find_channel(c, !pim->use_ipv6 ? NET_MREQ4 : NET_MREQ6));
  pim->mroute_channel = proto_add_channel(p, proto_cf_find_channel(c, !pim->use_ipv6 ? NET_MGRP4 : NET_MGRP6));

  p->rt_notify = pim_rt_notify;
  p->if_notify = pim_if_notify;
  p->rte_same = pim_rte_same;

  pim->rpf_update = ev_new(p->pool);
  pim->rpf_update->data = pim;
  pim->rpf_update->hook = pim_rpf_update;

  pim->cf = pim_c;

  return p;
}

struct protocol proto_pim = {
	.name =		"PIM",
	.template =	"pim%d",
	.preference =	DEF_PREF_STATIC,
	.channel_mask = NB_ANY,
	.proto_size =	sizeof(struct pim_proto),
	.config_size =	sizeof(struct pim_config),
	.init =		pim_init,
	.dump =		pim_dump,
	.start =	pim_start,
	.shutdown =	pim_shutdown,
};

