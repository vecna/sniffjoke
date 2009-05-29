/* ----------------------------------------------------------------------------- 
 * security.c
 *
 *     Various security mechanisms including user authentication and 
 *     IP filtering.
 * 
 * Author(s) : David Beazley (beazley@cs.uchicago.edu)
 *             Sotiria Lampoudi (slampoud@cs.uchicago.edu)
 *
 * Copyright (C) 1999-2002.  The University of Chicago
 * See the file LICENSE for information on usage and redistribution.	
 * ----------------------------------------------------------------------------- */

static char cvsroot[]="$Header: /cvsroot/swill/SWILL/Source/SWILL/security.c,v 1.2 2006/12/22 14:37:37 gonzalodiethelm Exp $";

#include "swillint.h"

static List *ip_allow = 0;
static List *ip_deny = 0;
static Hash   *SwillUsers   = 0;

/* Place IP addresses on the allow/deny lists */
void swill_allow(const char *ip) {
   if (!SwillInit) return;
   if (!ip_allow) {
      ip_allow = NewList();
      swill_deny("");
   }
   Append(ip_allow,ip);
}

void swill_deny(const char *ip) {
   if (!SwillInit) return;
   if (!ip_deny) ip_deny = NewList();
   Append(ip_deny,ip);
}

int swill_check_ip(const String *ip) {
   String *item;
   int     allow = 1;
  
   /* Look for denied addresses */
   if (ip_deny) {
      for (item = Firstitem(ip_deny); item; item = Nextitem(ip_deny)) {
	 if (Strncmp(item,ip,Len(item)) == 0) {
	    allow = 0;
	 }
      }
   }
   /* Look for allowed addresses */
   if (ip_allow) {
      for (item = Firstitem(ip_allow); item; item = Nextitem(ip_allow)) {
	 if (Strncmp(item,ip,Len(item)) == 0) {
	    return 1;
	 }
      }
   }
   return allow;
}

/* -----------------------------------------------------------------------------
 * swill_user()
 *
 * Adds a username and enables authentication for all pages.
 * ----------------------------------------------------------------------------- */

void
swill_user(const char *name, const char *password) {
   String *str;
   if (!SwillInit) return;
   if (!SwillUsers) {
      SwillUsers = NewHash();
   }
   str = NewString("");
   Printf(str,"%s:%s",name,password);
   Setattr(SwillUsers,str,name);
}

/* -----------------------------------------------------------------------------
 * swill_checkuser()
 *
 * Check for user authentication in a request
 * ----------------------------------------------------------------------------- */

int
swill_checkuser() {
   String *auths;
   String *userpw;
   int ch;
   char *auth;
   if (!SwillUsers) return 1;
   auth = swill_getheader("authorization");
   if (!auth) {
      return 0;
   }
   auths = NewString(auth);
   Seek(auths, 0, SEEK_SET);
   do {
      ch = Getc(auths);
   } while ((ch != EOF) && (ch != ' '));
   userpw = NewString("");
   swill_base64_decode(auths,userpw);
   if (Getattr(SwillUsers,userpw)) {
      Delete(auths);
      Delete(userpw);
      return 1;
   }
   Delete(auths);
   Delete(userpw);
   return 0;
}

void swill_security_init() {
   SwillUsers = 0;
   ip_allow = 0;
   ip_deny = 0;
}

void swill_security_reset() {
   if (SwillUsers) {
      Delete(SwillUsers);
      SwillUsers = 0;
   }
   if (ip_allow) {
      Delete(ip_allow);
      ip_allow = 0;
   }
   if (ip_deny) {
      Delete(ip_deny);
      ip_deny = 0;
   }
}
