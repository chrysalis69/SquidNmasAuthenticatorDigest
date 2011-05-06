/************************************************************************
 *	nmasPkt.h
 *
 *  (C) Copyright 2001-2007 Novell, Inc.
 *  All Rights Reserved.
 *
 *  This program is an unpublished copyrighted work which is proprietary
 *  to Novell, Inc. and contains confidential information that is not
 *  to be reproduced or disclosed to any other person or entity without
 *  prior written consent from Novell, Inc. in each and every instance.
 *
 *  WARNING:  Unauthorized reproduction of this program as well as
 *  unauthorized preparation of derivative works based upon the
 *  program or distribution of copies by sale, rental, lease or
 *  lending are violations of federal copyright laws and state trade
 *  secret laws, punishable by civil and criminal penalties.
 ****************************************************************************/

#define NMASLDAP_PUT_LOGIN_CONFIG_REQUEST     "2.16.840.1.113719.1.39.42.100.1"
#define NMASLDAP_PUT_LOGIN_CONFIG_RESPONSE    "2.16.840.1.113719.1.39.42.100.2"

#define NMASLDAP_GET_LOGIN_CONFIG_REQUEST     "2.16.840.1.113719.1.39.42.100.3"
#define NMASLDAP_GET_LOGIN_CONFIG_RESPONSE    "2.16.840.1.113719.1.39.42.100.4"

#define NMASLDAP_DELETE_LOGIN_CONFIG_REQUEST  "2.16.840.1.113719.1.39.42.100.5"
#define NMASLDAP_DELETE_LOGIN_CONFIG_RESPONSE "2.16.840.1.113719.1.39.42.100.6"

#define NMASLDAP_PUT_LOGIN_SECRET_REQUEST     "2.16.840.1.113719.1.39.42.100.7"
#define NMASLDAP_PUT_LOGIN_SECRET_RESPONSE    "2.16.840.1.113719.1.39.42.100.8"

#define NMASLDAP_DELETE_LOGIN_SECRET_REQUEST  "2.16.840.1.113719.1.39.42.100.9"
#define NMASLDAP_DELETE_LOGIN_SECRET_RESPONSE "2.16.840.1.113719.1.39.42.100.10"

#define NMASLDAP_SET_PASSWORD_REQUEST         "2.16.840.1.113719.1.39.42.100.11"
#define NMASLDAP_SET_PASSWORD_RESPONSE        "2.16.840.1.113719.1.39.42.100.12"

#define NMASLDAP_GET_PASSWORD_REQUEST         "2.16.840.1.113719.1.39.42.100.13"
#define NMASLDAP_GET_PASSWORD_RESPONSE        "2.16.840.1.113719.1.39.42.100.14"

#define NMASLDAP_DELETE_PASSWORD_REQUEST      "2.16.840.1.113719.1.39.42.100.15"
#define NMASLDAP_DELETE_PASSWORD_RESPONSE     "2.16.840.1.113719.1.39.42.100.16"

#define NMASLDAP_PASSWORD_POLICY_CHECK_REQUEST  "2.16.840.1.113719.1.39.42.100.17"
#define NMASLDAP_PASSWORD_POLICY_CHECK_RESPONSE "2.16.840.1.113719.1.39.42.100.18"

#define NMASLDAP_GET_PASSWORD_POLICY_INFO_REQUEST  "2.16.840.1.113719.1.39.42.100.19"
#define NMASLDAP_GET_PASSWORD_POLICY_INFO_RESPONSE "2.16.840.1.113719.1.39.42.100.20"

#define NMASLDAP_CHANGE_PASSWORD_REQUEST      "2.16.840.1.113719.1.39.42.100.21"
#define NMASLDAP_CHANGE_PASSWORD_RESPONSE     "2.16.840.1.113719.1.39.42.100.22"

#define NMASLDAP_GAMS_REQUEST                 "2.16.840.1.113719.1.39.42.100.23"
#define NMASLDAP_GAMS_RESPONSE                "2.16.840.1.113719.1.39.42.100.24"

#define NMASLDAP_NMAS_REQUEST                 "2.16.840.1.113719.1.39.42.100.25"
#define NMASLDAP_NMAS_RESPONSE                "2.16.840.1.113719.1.39.42.100.26"

/* NMASLDAP_NMAS_REQUEST operations */
#define NMAS_REFRESH_POLICY          1
#define NMAS_CHECK_LOGIN_POLICY      2
#define NMAS_SET_ADDRESS_POLICY      3
#define NMAS_GET_USER_RAND_PASSWORD  4
#define NMAS_GET_RAND_PASSWORD       5

#define NMAS_LDAP_EXT_VERSION 1

#define NMAS_LDAP_EXT_PWD_STATUS_VERSION 3

#define CHECK_CURRENT_PASSWORD      0x1
#define CHECK_PASSWORD_STATUS       0x2
#define CHECK_DIST_PASSWORD_STATUS  0x4



