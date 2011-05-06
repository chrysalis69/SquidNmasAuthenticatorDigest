/*
 * ldapFunctions.h
 *
 *  Created on: Jan 28, 2010
 *      Author: coetzeesj
 */

#ifndef LDAPFUNCTIONS_H_
#define LDAPFUNCTIONS_H_
#include "common.h"
#include "nmasext.h"
#include <ldap.h>
#include <getopt.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <sys/types.h>
#include <string.h>

extern void ProcessArguments(int argc, char **argv);
extern void GetPassword(RequestData *requestData);
extern void unBind();

#endif /* LDAPFUNCTIONS_H_ */
