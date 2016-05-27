/*
 *	BIRD -- PIM protocol
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include "pim.h"

static inline void
df_send(struct pim_rp_iface *rpi, uint type, ip_addr *target, struct pim_metric *target_metric)
{
  struct pim_df_msg msg;
  msg.type = type;
  msg.rpa = rpi->rp->rpa;
  msg.metric = pim_get_metric(rpi);

  if (target && target_metric)
  {
    msg.target = *target;
    msg.target_metric = *target_metric;
  }

  if (type == PIM_DF_BACKOFF)
    msg.backoff_interval = PIM_BACKOFF_PERIOD;

  pim_send_df(rpi, &msg);
}

static inline void
df_set_df(struct pim_rp_iface *rpi, struct pim_neigh *df, struct pim_metric metric)
{
  rpi->df_metric = metric;
  if (rpi->df == df)
    return;

  if (rpi->df)
    rem_node(&rpi->df_node);

  pim_upstream_neighbor_change(rpi->rp, rpi->df, df);

  rpi->df = df;

  if (df)
    add_tail(&df->df_list, &rpi->df_node);
}

static inline void
df_set_bo(struct pim_rp_iface *rpi, struct pim_neigh *bo, struct pim_metric metric)
{
  rpi->bo_metric = metric;
  if (rpi->bo)
    rem_node(&rpi->bo_node);
  rpi->bo = bo;
  if (bo)
    add_tail(&bo->bo_list, &rpi->bo_node);
}

static inline void
df_set_state(struct pim_rp_iface *rpi, uint state)
{
  if (rpi->election_state == state)
    return;

  int was_df = RPI_IS_DF(rpi);
  rpi->election_state = state;
  if (RPI_IS_DF(rpi))
    df_set_df(rpi, NULL, rpi->rp->rp_metric);

  if (was_df != RPI_IS_DF(rpi))
    pim_rp_update_routing(rpi->rp);
}


#define OP_HIGH (rpi->iface->cf->election_robustness * PIM_OFFER_PERIOD)
#define OP_LOW (PIM_OFFER_PERIOD * (random() & 128 + 128) / 256)

#define DFT(x)			tm_start_btime(rpi->election_timer, x)
#define DFT_LOWER(x)		tm_start_min_btime(rpi->election_timer, x);
#define DFT_STOP		tm_stop(rpi->election_timer)
#define MC(x)			rpi->mc = x
#define STATE(X)		df_set_state(rpi, PIM_DF_##X);
#define SEND(X)			df_send(rpi, PIM_DF_##X, NULL, NULL)
#define SEND_TARGET(X,y,z)	df_send(rpi, PIM_DF_##X, &y, &z)
#define DF_SENDER		df_set_df(rpi, msg->sender, msg->metric)
#define DF_TARGET		df_set_df(rpi, pim_neigh_from_neighbor(target), msg->target_metric)

#define CASE(state, better, msg) ((state << 4) | (msg << 1) | (better != 0))
#define C(state, better, msg) CASE(PIM_DF_##state, better, PIM_DF_##msg)

#define BETTER	1
#define WORSE	0

/*
 * This method handles the 21 different cases, so it's quite nasty.
 */
void
pim_df_message(struct pim_rp_iface *rpi, struct pim_df_msg *msg)
{
  neighbor *target = NULL;
  char better;

  if (msg->type >= PIM_DF_BACKOFF)
  {
    target = neigh_find2(&rpi->iface->proto->p, &msg->target, rpi->iface->iface, 0);

    if (target && target->scope == SCOPE_HOST)
    {
      // struct pim_proto *p = rpi->rp->proto;
      if (rpi->election_state == PIM_DF_OFFER)
      {
	if (msg->type == PIM_DF_PASS)
	{
	  STATE(WINNER);
	  DFT_STOP;
	}
	else
	{
	  DFT(OP_LOW + msg->backoff_interval);
	  MC(0);
	}
      }
      else
      {
	STATE(OFFER);
	DFT(OP_LOW);
	MC(0);
      }
      return;
    }

    better = pim_metric_better(&msg->target_metric, &rpi->rp->rp_metric, &msg->target, &rpi->iface->iface->addr->ip);
  }
  else
    better = pim_metric_better(&msg->metric, &rpi->rp->rp_metric, &msg->sender->neigh->addr,  &rpi->iface->iface->addr->ip);

  switch (CASE(rpi->election_state, better, msg->type))
    {
      case C(LOSE, BETTER, OFFER):
	STATE(OFFER);
      case C(OFFER, BETTER, OFFER):
	DFT(OP_HIGH);
	MC(0);
	return;

      case C(WINNER, BETTER, OFFER):
	STATE(BACKOFF);
      case C(BACKOFF, BETTER, OFFER):
	if (!rpi->bo || pim_metric_better(&msg->metric, &rpi->bo_metric, &msg->sender->neigh->addr, &rpi->bo->neigh->addr))
	  df_set_bo(rpi, msg->sender, msg->metric);
	SEND_TARGET(BACKOFF, msg->sender->neigh->addr, rpi->bo_metric);
	DFT(PIM_BACKOFF_PERIOD);
	return;

      case C(OFFER, WORSE, OFFER):
	DFT_LOWER(OP_LOW);
	MC(0);
	return;

      case C(BACKOFF, WORSE, OFFER):
	STATE(WINNER);
	DFT_STOP;
      case C(WINNER, WORSE, OFFER):
	SEND(WINNER);
	return;

      case C(OFFER, BETTER, WINNER):
      case C(WINNER, BETTER, WINNER):
      case C(BACKOFF, BETTER, WINNER):
      case C(WINNER, BETTER, BACKOFF):
      case C(BACKOFF, BETTER, BACKOFF):
	STATE(LOSE);
	DFT_STOP;
      case C(LOSE, BETTER, WINNER):
      case C(LOSE, BETTER, BACKOFF):
	DF_SENDER;
	return;

      case C(OFFER, BETTER, BACKOFF):
	DFT(msg->backoff_interval + OP_LOW);
	MC(0);
	return;

      case C(LOSE, WORSE, BACKOFF):
      case C(LOSE, WORSE, WINNER):
      case C(WINNER, WORSE, BACKOFF):
      case C(WINNER, WORSE, WINNER):
      case C(BACKOFF, WORSE, BACKOFF):
      case C(BACKOFF, WORSE, WINNER):
	DF_SENDER;
	STATE(OFFER);
	DFT(OP_LOW);
	MC(0);
	return;

      case C(LOSE, WORSE, OFFER):
	if (rpi->rp->upstream == NULL || rpi->rp->upstream == rpi)
	  /**
	   * When there is a link with more than one router, but all of them
	   * without path to RPA, an infinite election occurs. One router wins the
	   * election, but does not announce itself a winner. That is the same as
	   * if it died just before winning, resulting in other routers restarting
	   * the election.
	   * Do not answering the worse offers, when out metric is infinite, may
	   * not break the protocol, because the offering metric is also infinite.
	   * The protocols should fall into such losing misery one by one, until
	   * the last one loses.
	   */
	  break;
	STATE(OFFER);
	DFT(OP_LOW);
	MC(0);
	return;

      case C(OFFER, WORSE, BACKOFF):
      case C(OFFER, WORSE, WINNER):
	DF_SENDER;
	DFT_LOWER(OP_LOW);
	MC(0);
	return;

      case C(OFFER, BETTER, PASS):
      case C(WINNER, BETTER, PASS):
      case C(BACKOFF, BETTER, PASS):
	DFT_STOP;
      case C(LOSE, BETTER, PASS):
	DF_TARGET;
	return;

      case C(OFFER, WORSE, PASS):
	DF_TARGET;
	DFT_LOWER(OP_LOW);
	MC(0);
	return;

      case C(WINNER, WORSE, PASS):
      case C(BACKOFF, WORSE, PASS):
      case C(LOSE, WORSE, PASS):
	STATE(OFFER);
	DF_TARGET;
	DFT(OP_LOW);
	MC(0);
	return;

      default:
	bug("Invalid DF state %u, msg %u with %s metric", rpi->election_state, msg->type, better ? "better" : "worse");
	return;
    }
}

void
pim_df_timer_expired(timer *t)
{
  struct pim_rp_iface *rpi = t->data;
  struct pim_proto *p = rpi->rp->proto;
  switch (rpi->election_state)
  {
    case PIM_DF_OFFER:
      if (rpi->mc >= rpi->iface->cf->election_robustness)
	{
	  if (rpi->rp->upstream && rpi->rp->upstream != rpi)
	    {
	      TRACE(D_EVENTS, "Finished offering: taking over DF on link %s.", rpi->iface->iface->name);
	      STATE(WINNER);
	      SEND(WINNER);
	    }
	  else
	    {
	      TRACE(D_EVENTS, "Finished offering, no upstream: losing.");
	      STATE(LOSE);
	      df_set_df(rpi, NULL, PIM_METRIC_INFTY);
	      DFT_STOP;
	    }
	}
      else
	{
	  rpi->mc++;
	  SEND(OFFER);
	  DFT(OP_LOW);
	}
      break;
    case PIM_DF_WINNER:
      if (rpi->mc < rpi->iface->cf->election_robustness)
	{
	  rpi->mc++;
	  SEND(WINNER);
	  DFT(OP_LOW);
	}
      break;
    case PIM_DF_BACKOFF:
      STATE(LOSE);
      SEND_TARGET(PASS, rpi->bo->neigh->addr, rpi->bo_metric);
      df_set_df(rpi, rpi->bo, rpi->bo_metric);
      DFT_STOP;
      df_set_bo(rpi, NULL, PIM_METRIC_INFTY);
      break;
    case PIM_DF_LOSE:
    default:
      break;
  }
}

void
pim_df_reelect(struct pim_rp_iface *rpi)
{
  MC(0);
  DFT(OP_LOW);
}

void
pim_df_metric_changed(struct pim_rp_iface *rpi, struct pim_metric old_metric)
{
  struct pim_metric new_metric = pim_get_metric(rpi);
  switch (rpi->election_state)
    {
      case PIM_DF_OFFER:
      case PIM_DF_WINNER:
	if (!pim_metric_better(&new_metric, &old_metric, NULL, NULL))
	  pim_df_reelect(rpi);
	break;
      case PIM_DF_BACKOFF:
      case PIM_DF_LOSE:
	if (!rpi->df || pim_metric_better(&new_metric, &rpi->df_metric, &rpi->iface->iface->addr->ip, &rpi->df->neigh->addr))
	  {
	    df_set_state(rpi, rpi->election_state == PIM_DF_BACKOFF ? PIM_DF_WINNER : PIM_DF_OFFER);
	    pim_df_reelect(rpi);
	  }

    }
}
