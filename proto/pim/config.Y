/*
 *  BIRD -- PIM protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/pim/pim.h"

CF_DEFINES

#define PIM_CFG ((struct pim_config *) this_proto)
#define PIM_IFACE ((struct pim_iface_config *) this_ipatt)

static struct pim_grp_config *this_group;

CF_DECLS

CF_KEYWORDS(PIM, GROUP, RPA, SUBSCRIBE, HELLO, PERIOD, DELAY, HOLDTIME)
CF_KEYWORDS(ELECTION, ROBUSTNESS, OVERRIDE, INTERVAL, JOINPRUNE, SUPPRESSION)

CF_GRAMMAR

CF_ADDTO(proto, pim_proto '}' { pim_config_finish(PIM_CFG); } )

pim_proto_start: proto_start PIM {
   this_proto = proto_config_new(&proto_pim, $1);
   pim_config_init(PIM_CFG);
 }
 ;

pim_proto:
   pim_proto_start proto_name '{'
 | pim_proto pim_proto_item ';'
 ;

pim_proto_item:
   proto_item
 | proto_channel
 | pim_group
 | INTERFACE pim_iface
 ;

pim_group_start:
 GROUP net_or_ipa {
  this_group = cfg_allocz(sizeof(struct pim_grp_config));
  add_tail(&PIM_CFG->grp_list, NODE this_group);
  this_group->ga = $2; 
 }
 ;

pim_group_item:
 RPA ipa { this_group->rpa = $2; }
 ;

pim_group_opts:
   /* empty */
 | pim_group_opts pim_group_item ';'
 ;

pim_group:
  pim_group_start '{' pim_group_opts '}'
 ;

pim_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct pim_iface_config));
  add_tail(&PIM_CFG->patt_list, NODE this_ipatt);
  pim_iface_config_init(PIM_IFACE);
};

pim_iface_item:
   HELLO PERIOD expr_us { PIM_IFACE->hello_int = $3; }
 | HELLO DELAY expr_us { PIM_IFACE->hello_dly = $3; }
 | HELLO HOLDTIME expr_us { PIM_IFACE->hello_holdtime = $3; }
 | ELECTION ROBUSTNESS expr { PIM_IFACE->election_robustness = $3; }
 | OVERRIDE INTERVAL expr_us { PIM_IFACE->override_interval = $3; }
 | JOINPRUNE PERIOD expr_us { PIM_IFACE->jp_periodic = $3; }
 | JOINPRUNE HOLDTIME expr_us { PIM_IFACE->jp_holdtime = $3; }
 ;

pim_iface_opts:
   /* empty */
 | pim_iface_opts pim_iface_item ';'
 ;

pim_iface_opt_list:
   /* empty */
 | '{' pim_iface_opts '}'
 ;

pim_iface:
  pim_iface_start iface_patt_list_nopx pim_iface_opt_list { pim_iface_config_finish(PIM_IFACE); }



CF_CODE

CF_END
