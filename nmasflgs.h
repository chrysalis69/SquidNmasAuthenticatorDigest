/************************************************************************
 *
 *  (C) Copyright 2004-2007 Novell, Inc.
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
 *
 ****************************************************************************/
#ifndef __NMASFLGS_H
#define __NMASFLGS_H

// Universal Password Status flags
#define SPM_UPWD_ENABLED        0x1
#define SPM_UPWD_SET            0x2
#define SPM_UPWD_HISTORY_FULL   0x4
#define SPM_UPWD_MATCHES_NDS    0x10
#define SPM_UPWD_OLDER_THAN_NDS 0x20
#define SPM_UPWD_MATCHES_SPWD   0x40
#define SPM_DPWD_SET            0x100
#define SPM_UPWD_MATCHES_DPWD   0x200
#define SPM_UPWD_SET_BY_ADMIN   0x1000

// Simple Password Status flags
#define SPM_SPWD_SET            0x1
#define SPM_SPWD_IS_CLEARTEXT   0x2
#define SPM_SPWD_MATCHES_NDS    0x10

/* Login Policy Check flags */
#define LOGIN_POLICY_CHECK              0x1
#define LOGIN_POLICY_SUCCESS_UPDATE     0x2
#define LOGIN_POLICY_FAILURE_UPDATE     0x4
#define LOGIN_POLICY_PWD_POLICY_CHECK   0x8

/* Set Address Policy flags */
#define LOGIN_POLICY_ADD_RESTRICTION    0x1
#define LOGIN_POLICY_RM_RESTRICTION     0x2

#endif

/************************************************************************/
/************************************************************************/
