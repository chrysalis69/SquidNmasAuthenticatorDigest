/*
 * ldapFunctions.c
 *
 *  Created on: Jan 28, 2010
 *      Author: coetzeesj
 */

#include "ldapFunctions.h"

// Configuration Variables
static char *opt_URI, *opt_bindDN, *opt_searchBase;
static char **attrs = (char*[]){"ufsEmplNum","ufsStudNum","ufsInternetStatus","ufsInternetStatusDesc","ufsNID",NULL};
int opt_ldapSearchScope = LDAP_SCOPE_DEFAULT;
int opt_URI_count;

BerValue opt_bindPassword;

static LDAP *ldap_connection = NULL;

void PrintUsage(char *AppName)
{
	fprintf(stdout, "usage: %s [options] [filter]\noptions:\n\t-h host\tLDAP Server\n\t-p port\tport on LDAP Server\n\t-H URI\tLDAP Uniform Resource Identifier(s)\n", AppName);
}

void ProcessArguments(int argc, char **argv)
{
	char *optargLower;
	int c, rc, *msgid;
	while((c = getopt(argc, argv, ":H:D:w:b:s:")) != -1)
		{
			switch(c)
			{
				case 'H' :
					opt_URI = strdup(optarg);
					break;
				case 'D' :
					opt_bindDN = optarg;
					break;
				case 'w' :
					opt_bindPassword.bv_val = ber_strdup(optarg);
					opt_bindPassword.bv_len = strlen(opt_bindPassword.bv_val);
					break;
				case 'b' :
					opt_searchBase = optarg;
					break;
				case 's' :
					for (optargLower = optarg; *optargLower; optargLower++)
						*optargLower = tolower(*optargLower);
					if (strcmp(optarg, "base") == 0) opt_ldapSearchScope = LDAP_SCOPE_BASE;
					if (strcmp(optarg, "sub") == 0) opt_ldapSearchScope = LDAP_SCOPE_SUBTREE;
					if (strcmp(optarg, "one") == 0) opt_ldapSearchScope = LDAP_SCOPE_ONE;
					if (strcmp(optarg, "children") == 0) opt_ldapSearchScope = LDAP_SCOPE_CHILDREN;
					break;
				case ':' :
					fprintf(stderr, "%s: option '-%c' requires an argument\n", argv[0], optopt);
					PrintUsage(argv[0]);
					exit(1);
					break;
				case '?' :
					fprintf(stderr, "%s: option '-%c' is invalid: ignored\n", argv[0], optopt);
					PrintUsage(argv[0]);
					exit(1);
					break;
			}
	}
}

void ProcessConfiguration(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "%s: Please use syntax %s <configfile>\n", argv[0], argv[0]);
	}
	FILE *fp = fopen(argv[1], "r");
	if(fp == NULL)
	{
		fprintf(stderr, "%s: Not a valid config file.\n", argv[0]);
		exit(1);
	}
	char *option;//[256];
	char *optionValue;//[256];
	while(!feof(fp))
	{
		char buffer[256];
		int num_chars = 0;
		int ch = fgetc(fp);
		for(ch; ch != EOF && ch != '\n' && num_chars < 244 ; ch = fgetc(fp))
		{
			buffer[num_chars++] = ch;
		}
		buffer[num_chars] = '\0';
		if ((option = strtok(buffer, "=")) == NULL) continue;
		if ((optionValue = strtok(NULL, "\n")) == NULL) continue;
		if (strcasecmp(option,"URI") == 0)
		{
			opt_URI = malloc(strlen(optionValue));
			strcpy(opt_URI, optionValue);
		}
		if (strcasecmp(option, "bindDN") == 0) {
			opt_bindDN = malloc(strlen(optionValue));
			strcpy(opt_bindDN, optionValue);
		}
		if (strcasecmp(option, "bindPassword") == 0)
		{
			opt_bindPassword.bv_val = ber_strdup(optionValue);
			opt_bindPassword.bv_len = strlen(opt_bindPassword.bv_val);
		}
		if (strcasecmp(option, "searchBase") == 0)
		{
			opt_searchBase = malloc(strlen(optionValue));
			strcpy(opt_searchBase, optionValue);
		}
		if (strcasecmp(option, "searchScope") == 0)
		{
			if (strcasecmp(optionValue, "base") == 0) opt_ldapSearchScope = LDAP_SCOPE_BASE;
			if (strcasecmp(optionValue, "sub") == 0) opt_ldapSearchScope = LDAP_SCOPE_SUBTREE;
			if (strcasecmp(optionValue, "one") == 0) opt_ldapSearchScope = LDAP_SCOPE_ONE;
			if (strcasecmp(optionValue, "children") == 0) opt_ldapSearchScope = LDAP_SCOPE_CHILDREN;
		}
	}
	fclose(fp);
}

char *strstrrep(char *dest, const char *haystack, const char *needle, const char *replace)
{
	dest = malloc(strlen(haystack)-strlen(needle)+strlen(replace)+1);
	*dest = '\0';
	char *p = strstr(haystack, needle);
	strncat(dest, haystack, p-haystack);
	strcat(dest, replace);
	p = p+strlen(needle);
	strcat(dest,p);
	p = NULL;
	return dest;
}

void unBind()
{
	if (ldap_connection != NULL)
	{
		ldap_unbind_ext(ldap_connection, NULL, NULL);
		ldap_connection = NULL;
	}
}

int Bind()
{
	int rc, *msgid;
	if (ldap_connection == NULL)
		{
			if (strstr(opt_URI, "://") != NULL)
			{
				rc = ldap_initialize(&ldap_connection, opt_URI);
				if (rc != LDAP_SUCCESS)
				{
					fprintf(stderr, "Unable to connect to LDAPURI:%s\n", opt_URI);
					exit(rc);
				}
				int *ldap_version = LDAP_VERSION3;
				if ((rc = ldap_set_option(ldap_connection, LDAP_OPT_PROTOCOL_VERSION, &ldap_version)) != LDAP_SUCCESS)
				{
					fprintf(stderr, "Could not set LDAP Version\n");
					exit(rc);
				}
				rc = ldap_sasl_bind_s(ldap_connection, opt_bindDN, LDAP_SASL_SIMPLE, &opt_bindPassword, NULL, NULL, &msgid);
				if (rc != LDAP_SUCCESS)
				{
					fprintf(stderr, "LDAP Bind error %d: %s\n", rc, ldap_err2string(rc));
					exit(rc);
				}
			}
		}
}

char *BuildLdapFilter(const char *user)
{
	char *ldapFilter;
	char *persno;
	int rc;
	if ((rc = regexec(&pattern_pers_no, user, 0, NULL, 0)) == 0)
	{
		persno = malloc(8);
		sprintf(persno, "%07d", strtol(user, NULL, 10));
		char *ldapFilter = strstrrep(ldapFilter, SLA_LDAP_SEARCH_PERS_NO, "%user%", persno);
		free(persno);
		return ldapFilter;
	}
	else if ((rc = regexec(&pattern_stud_no, user, 0, NULL, 0)) == 0)
	{
		char *ldapFilter;
		return strstrrep(ldapFilter, SLA_LDAP_SEARCH_STUD_NO, "%user%", user);
	}else
	{
		char *ldapFilter;
		return strstrrep(ldapFilter, SLA_LDAP_SEARCH_PERS_CN, "%user%", user);
	}
	return NULL;
}

void GetPassword(RequestData *requestData)
{
	int 					rc, *msgid;
	BerElement              *ber = NULL;
	struct berval           bv, *bvals, **bvp = &bvals;
	ber_int_t 				msgsid;
	LDAPMessage 			*res, *msg;
	char 					*ufsInternetStatus = NULL, *ufsNID = NULL, *ldapFilter = NULL, *dn = NULL;


	if ((ldapFilter = BuildLdapFilter(requestData->user)) == NULL)
	{
		requestData->error = SLA_ERR_MALFORMED_USER;
		return;
	}
	Bind();
	rc = ldap_search_ext(ldap_connection, opt_searchBase, opt_ldapSearchScope, ldapFilter, attrs, 0, NULL, NULL, NULL, -1, &msgid);
	free(ldapFilter);
	if (rc != LDAP_SUCCESS)
	{
		fprintf(stderr, "LDAP search error %d: %s\n", rc, ldap_err2string(rc));
		requestData->error = SLA_ERR_LDAP_ERR;
		return;
	}
	res = NULL;
	while ((rc = ldap_result(ldap_connection, LDAP_RES_ANY, LDAP_MSG_ONE, NULL, &res )) >0 )
	{
		for(msg = ldap_first_message(ldap_connection, res);
				msg != NULL;
				msg = ldap_next_message(ldap_connection, msg))
		{
			int lMsgType = ldap_msgtype(msg);
			switch (lMsgType)
			{
				case LDAP_RES_SEARCH_RESULT:
					rc = 0;
					int err;
					char *matcheddn = NULL;
					char *text = NULL;
					char **refs = NULL;
					rc = ldap_parse_result(ldap_connection, msg, &err, &matcheddn, &text, &refs, NULL, 0);
					if (rc != LDAP_SUCCESS)
					{
						fprintf(stderr, "ldap_parse_result error %d: %s\n", rc, ldap_err2string(rc));
						exit(rc);
					}
					if (err == LDAP_PARTIAL_RESULTS)
						break;
					goto done;
					break;
				case LDAP_RES_SEARCH_ENTRY :
					rc = ldap_get_dn_ber(ldap_connection, msg, &ber, &bv);
					if (rc == LDAP_SUCCESS)
					{
						if (bv.bv_val == NULL)
						{
							break;
						}
						dn = strdup(bv.bv_val);
						if (debug) printf("%s\n",bv.bv_val);
						for (rc = ldap_get_attribute_ber(ldap_connection, msg, ber, &bv, bvp);
								rc == LDAP_SUCCESS;
								rc = ldap_get_attribute_ber(ldap_connection, msg, ber, &bv, bvp))
						{
							if (bv.bv_val == NULL)
							{
								break;
							}
							if (strcasecmp(bv.bv_val, "ufsnid") == 0) ufsNID = strdup(bvals->bv_val);
							if (strcasecmp(bv.bv_val, "ufsinternetstatus") == 0) ufsInternetStatus = strdup(bvals->bv_val);
							//if (strcasecmp(bv.bv_val, "ufsstudnum") == 0) requestData->returnUser = strdup(bvals->bv_val);
							//if (strcasecmp(bv.bv_val, "ufsemplnum") == 0) requestData->returnUser = strdup(bvals->bv_val);
							if (debug) printf("\t%s:\t%s\n",bv.bv_val,bvals->bv_val);
							ber_memfree(bvals);
						}
					}
					ber_free(ber, 0);
					break;
			}

		}
		ldap_msgfree(res);
	}
	done:
	if (res != NULL) ldap_msgfree(res);
	if (ufsInternetStatus == NULL)
	{
		requestData->error = SLA_ERR_AUTH_NO_REC;
		return;
	}else
	if (strcasecmp(ufsInternetStatus, SLA_AUTH_NMAS) == 0)
	{
		char pwd[512];
		int pwdLen = sizeof(pwd);
		rc = nmasldap_get_password(ldap_connection, dn, &pwdLen, &pwd);
		if(rc)
		{
			requestData->error = SLA_ERR_NMAS_PASSWORD;
		}
		else
		{
			requestData->password = strdup(pwd);
		}
	}else
	if (strcasecmp(ufsInternetStatus, SLA_AUTH_NID) == 0)
	{
		if (ufsNID != NULL)
		{
			requestData->password = ufsNID;
			ufsNID = NULL;
		}
		else
			requestData->error = SLA_ERR_MALFORMED_USER;
	}else
	if (strcasecmp(ufsInternetStatus, SLA_AUTH_DISABLED_SYSTEM) == 0)
		requestData->error = SLA_ERR_AUTH_DISABLED_SYSTEM;
	free(dn);
	free(ufsInternetStatus);
	free(ufsNID);
	unBind();
	return;
}
