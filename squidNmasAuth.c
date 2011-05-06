/*
 * squidNmasAuth.c
 *
 *  Created on: Jan 26, 2010
 *      Author: coetzeesj
 */

#include "common.h"
#include "ldapFunctions.h"
#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>

#define PROGRAM_NAME "SquidLdapAuthenticator"
#define AUTHOR N_ ("Stefan Coetzee")

static void ParseBuffer(char *buf, RequestData *requestData)
{
	char *pointer;
	requestData->parsed = 0;
	if ((pointer = strchr(buf, '\n')) != NULL) *pointer = '\0';
	if ((requestData->user = strtok(buf, "\"")) == NULL) return;
	if ((requestData->realm = strtok(NULL, "\"")) == NULL) return;
	if ((requestData->realm = strtok(NULL, "\"")) == NULL) return;
	requestData->parsed = -1;
}

static void GetHHA1(RequestData *requestData)
{
	EVP_MD_CTX ctx;
	int *rc, rEVP;
	unsigned char md_value[EVP_MAX_MD_SIZE];

	GetPassword(requestData);

	if (!requestData->error)
	{
		int i;
		char *hha1 = malloc(strlen(requestData->user)+strlen(requestData->realm)+strlen(requestData->password)+4);
		*hha1 = '\0';
		strcat(hha1,requestData->user);
		strcat(hha1, ":");
		strcat(hha1, requestData->realm);
		strcat(hha1, ":");
		strcat(hha1, requestData->password);
		OpenSSL_add_all_digests();
		EVP_MD_CTX_init(&ctx);
		const EVP_MD *md = EVP_get_digestbyname("md5");
		rEVP = EVP_DigestInit_ex(&ctx, md, NULL);
		rEVP = EVP_DigestUpdate(&ctx, hha1, strlen(hha1));
		rEVP = EVP_DigestFinal_ex(&ctx, md_value, &rc);
		rEVP = EVP_MD_CTX_cleanup(&ctx);
		if (rc == NULL)
		{
			requestData->error = SLA_ERR_HASH;
		}
		requestData->HHA1 = malloc(33);
		*requestData->HHA1 = '\0';
		char tmp[10];
		if (debug)
		{
			for(i=0; i < rc; i++) printf("%02x", md_value[i]);
			printf("\n");
		}
		for(i=0; i < rc; i++)
			{
				sprintf(tmp, "%02x", md_value[i]);
				strcat(requestData->HHA1 ,tmp);
			}
		free(hha1);
	}
	return;
}

static void PrintHHA1(RequestData *requestData)
{
	requestData->error = 0;
	GetHHA1(requestData);
	if (requestData->error)
	{
		printf("ERR %d\n",requestData->error);
		return;
	}
	printf("%s\n", requestData->HHA1);
	free(requestData->HHA1);
	//free(requestData->returnUser);
	free(requestData->password);
}

static void DoRequest(char *buf)
{
	RequestData requestData;
	ParseBuffer(buf, &requestData);
	if (!requestData.parsed)
	{
		printf("ERR\n");
		return;
	}
	PrintHHA1(&requestData);
}

int main(int argc, char **argv)
{
	//Initialize Regex Structures
	char error[512];
	//Personel
	int rc = regcomp(&pattern_pers_no, SLA_PAT_PERS, REG_NOSUB|REG_EXTENDED);
	if (rc != 0)
	{
		regerror(rc, &pattern_pers_no, error, sizeof(error));
		fprintf(stderr, "%s: pattern '%s' : %s\n", argv[0], SLA_PAT_PERS, error);
		exit(rc);
	}
	//Students
	rc = regcomp(&pattern_stud_no, SLA_PAT_STUD, REG_NOSUB|REG_EXTENDED);
	if (rc != 0)
	{
		regerror(rc, &pattern_pers_no, error, sizeof(error));
				fprintf(stderr, "%s: pattern '%s' : %s\n", argv[0], SLA_PAT_STUD, error);
				exit(rc);
	}
	char buf[256];
 	setbuf(stdout, NULL);
	//ProcessArguments(argc, argv);
 	ProcessConfiguration(argc, argv);
	while (fgets(buf, 256, stdin) != NULL)
		DoRequest(buf);
	unBind();
	exit(0);
}

