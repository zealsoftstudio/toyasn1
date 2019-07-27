/* packet-toyasn1.c
 * Routines for toyasn1 packet dissection
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-ber.h>

#include <stdio.h>
#include <string.h>

#include "packet-toyasn1.h"

#define PNAME  "Toy ASN.1"
#define PSNAME "toyasn1"
#define PFNAME "toyasn1"
#define TOYASN1_PORT 0    /* TCP port */

/* Initialize the protocol and registered fields */
static int proto_toyasn1 = -1;
static int global_toyasn1_port = TOYASN1_PORT;
static dissector_handle_t toyasn1_handle;

#include "packet-toyasn1-hf.c"

/* Initialize the subtree pointers */
static int ett_toyasn1 = -1;

#include "packet-toyasn1-ett.c"

#include "packet-toyasn1-fn.c"


static int
dissect_toyasn1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item      *toyasn1_item = NULL;
    proto_tree      *toyasn1_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the toyasn1 protocol tree */
    if (tree) {
        toyasn1_item = proto_tree_add_item(tree, proto_toyasn1, tvb, 0, -1, FALSE);
        toyasn1_tree = proto_item_add_subtree(toyasn1_item, ett_toyasn1);
        dissect_TOYASN1_MESSAGE_PDU(tvb, pinfo, toyasn1_tree, NULL);
    }
	return tvb_captured_length(tvb);
}
/*--- proto_register_toyasn1 -------------------------------------------*/
void proto_register_toyasn1(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-toyasn1-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_toyasn1,
#include "packet-toyasn1-ettarr.c"
  };


  /* Register protocol */
  proto_toyasn1 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_toyasn1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


/*--- proto_reg_handoff_toyasn1 ---------------------------------------*/
void
proto_reg_handoff_toyasn1(void)
{
  toyasn1_handle = create_dissector_handle(dissect_toyasn1, proto_toyasn1);
  dissector_add_uint_with_preference("tcp.port", global_toyasn1_port, toyasn1_handle);
}
