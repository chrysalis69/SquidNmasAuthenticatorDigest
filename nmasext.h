/******************************************************************************
* Copyright (C) 2002-2007 Novell, Inc. All Rights Reserved.
*
* You may use the contents of this file subject to the terms of version 2 of 
* the GNU General Public License (GPL), or alternatively the MIT License, as 
* described below.  If you wish to allow use of your version of this file only
* under the terms of one of the licenses, indicate your decision by deleting 
* the provisions of the other license.
*
* GNU GENERAL PUBLIC LICENSE
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of version 2 of the GNU General Public License as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more 
* details.
*
* You should have received a copy of the GNU General Public License along with
* this program; if not, contact Novell, Inc.
*
* To contact Novell about this file by physical or electronic mail, you may 
* find current contact  information at www.novell.com.
*
* THE MIT LICENSE
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in 
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

#ifndef  NMASEXT_H
#define  NMASEXT_H

#include <ldap.h>
#include <nmasflgs.h>

#ifdef __cplusplus
   extern "C" {
#endif

int nmasldap_put_login_config(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int methodIDLen,
	unsigned int *methodID,
	char         *tag,
	size_t       dataLen,
	void         *data );

int nmasldap_delete_login_config(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int methodIDLen,
	unsigned int *methodID,
	char         *tag);

int nmasldap_get_login_config(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int methodIDLen,
	unsigned int *methodID,
	char         *tag,
	size_t       *dataLen,
	void         *data );

int nmasldap_put_login_secret(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int methodIDLen,
	unsigned int *methodID,
	char         *tag,
	size_t       dataLen,
	void        *data );

int nmasldap_delete_login_secret(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int methodIDLen,
	unsigned int *methodID,
	char         *tag);

int nmasldap_put_simple_pwd(
	LDAP	   *ld,
	char     *objectDN,
	char     *pwd );

int nmasldap_delete_simple_pwd(
	LDAP	   *ld,
	char     *objectDN);

int nmasldap_get_simple_pwd(
	LDAP	   *ld,
	char     *objectDN,
	size_t	pwdLen,
	char     *pwd );

int nmasldap_set_password(
	LDAP	   *ld,
	char     *objectDN,
	char     *pwd );

int nmasldap_get_password(
	LDAP	   *ld,
	char     *objectDN,
	size_t   *pwdSize,	// in bytes
	char     *pwd );

int nmasldap_delete_password(
	LDAP	   *ld,
	char     *objectDN);

int nmasldap_change_password(
	LDAP	   *ld,
	char     *objectDN,
	char     *oldPwd,
	char     *pwd );

int nmasldap_policy_check_password(
	LDAP	   *ld,
	char     *objectDN,
	char     *pwd );

int nmasldap_policy_check_current_password(
	LDAP	 *ld,
	char   *objectDN);

int nmasldap_get_password_status(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int *pwdStatus,
	unsigned int *simplePwdStatus);


#define NMAS_LDAP_PWD_STATUS_VERSION1 1
#define NMAS_LDAP_PWD_STATUS_VERSION2 2
#define NMAS_LDAP_PWD_STATUS_VERSION3 3
int nmasldap_get_password_status_ex(
	LDAP	       *ld,
	char         *objectDN,
	unsigned int *serverVersion,
	unsigned int *pwdStatus,
	unsigned int *simplePwdStatus);

int nmasldap_get_password_policy_dn(
	LDAP	   *ld,
	char     *objectDN,
	size_t   *dnSize,	// in bytes
	char     *dn );

int nmasldap_policy_refresh(
	LDAP	 *ld);

int nmasldap_check_login_policy(
	LDAP	         *ld,
	char           *objectDN,
   unsigned int   flags,
   size_t         netAddressSize,
   unsigned char  *netAddress);

int nmasldap_set_address_policy(
	LDAP	         *ld,
	char           *objectDN,
   unsigned int   flags,
   size_t         netAddressSize,
   unsigned char  *netAddress);

int nmasldap_get_user_random_password(
	LDAP	   *ld,
	char     *objectDN,
	size_t   *pwdSize,	// in bytes
	char     *pwd );

int nmasldap_get_random_password(
	LDAP	   *ld,
   char     *xmlPwdPolicy,
	size_t   *pwdSize,	// in bytes
	char     *pwd );


#ifdef __cplusplus
   }
#endif

#endif



