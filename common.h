/*
 * common.h
 *
 *  Created on: Jan 26, 2010
 *      Author: coetzeesj
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <regex.h>

#define SLA_AUTH_NMAS				"nmas"
#define SLA_AUTH_NID				"nid"
#define SLA_AUTH_DISABLED_SYSADMIN	"disabled-sysadmin"
#define SLA_AUTH_DISABLED_SYSTEM	"disabled"
#define SLA_AUTH_DISABLED_USER		"disabled-user"

#define SLA_ERR_AUTH_EXPIRE 			3
#define SLA_ERR_AUTH_NO_REC 			4
#define SLA_ERR_AUTH_DISABLED_SYSADMIN	5
#define SLA_ERR_AUTH_DISABLED_SYSTEM	6
#define SLA_ERR_AUTH_DISABLED_USER		7
#define SLA_ERR_HASH					8
#define SLA_ERR_MALFORMED_USER			9
#define SLA_ERR_NMAS_PASSWORD			10
#define SLA_ERR_LDAP_ERR				11

#define SLA_PAT_PERS					"^(([0-9]){3,7})$"
#define SLA_PAT_STUD					"^([1-3]([0-9]){9})$"

#define SLA_LDAP_SEARCH_PERS_NO			"(&(ufsEmplNum=%user%)(ufsActiveEmpl=true))"
#define SLA_LDAP_SEARCH_STUD_NO			"(&(ufsStudNum=%user%)(ufsActiveStud=true))"
#define SLA_LDAP_SEARCH_PERS_CN			"(&(ufsEmplCN=%user%)(ufsActiveEmpl=true))"

static const int debug = 0;
regex_t pattern_pers_no;
regex_t pattern_stud_no;

typedef struct _request_data {
	char *user;
	char *realm;
	char *password;
	char *HHA1;
	//char *returnUser;
	int parsed;
	int error;
} RequestData;

void PrintUsage(char *);

#endif /* COMMON_H_ */
