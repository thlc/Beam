/*
 * Copyright 2002-2006, project beam (http://sourceforge.net/projects/beam).
 * All rights reserved. Distributed under the terms of the GNU GPL v2.
 *
 * Authors:
 *		Oliver Tappe <beam@hirschkaefer.de>
 */

#ifndef _BmImapAccount_h
#define _BmImapAccount_h

#include <map>

#include "BmMailKit.h"

#include "BmRecvAccount.h"

using std::map;

enum {
	BM_JOBWIN_IMAP = 'bmei'
	// sent to JobMetaController (or app) in order to
	// start pop-connection
};

// IMAP flag bitmask values, shared between BmImap (src-bmDaemon, which does
// the actual protocol talk) and BmMailRef (this library, which needs to
// queue outbound flag-changes without depending on src-bmDaemon):
enum {
	BM_IMAP_FLAG_SEEN = 1 << 0,
	BM_IMAP_FLAG_ANSWERED = 1 << 1,
	BM_IMAP_FLAG_FLAGGED = 1 << 2,
	BM_IMAP_FLAG_DELETED = 1 << 3,
	BM_IMAP_FLAG_DRAFT = 1 << 4
};

/*------------------------------------------------------------------------------*\
	BmImapAccount
		-	holds information about one specific IMAP-account
		- 	extends BmRecvAccount with IMAP-specific functionality
\*------------------------------------------------------------------------------*/
class IMPEXPBMMAILKIT BmImapAccount : public BmRecvAccount {
	typedef BmRecvAccount inherited;

public:
	BmImapAccount(const char* name, BmRecvAccountList* model);
	BmImapAccount(BMessage* archive, BmRecvAccountList* model);
	virtual ~BmImapAccount();

	// overrides of BmRecvAccount base:
	virtual const char* Type() const { return nType; }
	virtual int32 JobType() const { return BM_JOBWIN_IMAP; }

	virtual const char* DefaultPort(bool encrypted) const { return encrypted ? "993" : "143"; }

	virtual void GetSupportedAuthTypes(vector<BmString>& outList) const;

	// per-folder UID tracking:
	//		-	IMAP UIDs are only unique within a single mailbox, so (unlike
	//			POP) we cannot use the flat mUIDs map inherited from
	//			BmRecvAccount; instead we keep one UID-map per remote folder.
	bool IsUIDDownloaded(const BmString& remoteFolder, const BmString& uid) const;
	void MarkUIDAsDownloaded(const BmString& remoteFolder, const BmString& uid);
	bool ShouldUIDBeDeletedFromServer(
		const BmString& remoteFolder, const BmString& uid, BmString& logOutput) const;
	BmString AdjustToCurrentServerUids(
		const BmString& remoteFolder, const vector<BmString>& serverUids);

	BmString UidValidityForFolder(const BmString& remoteFolder) const;
	void UidValidityForFolder(const BmString& remoteFolder, const BmString& uidValidity);

	// per-folder outbound flag-change queue:
	//		-	local status/flagged changes to IMAP-origin mail are queued
	//			here (keyed by remote folder + uid), and flushed as UID STORE
	//			commands at the start of the next check for that folder.
	void QueueOutboundFlags(const BmString& remoteFolder, const BmString& uid, uint32 flags);
	map<BmString, uint32> PendingOutboundFlags(const BmString& remoteFolder) const;
	void ClearPendingOutboundFlags(const BmString& remoteFolder, const BmString& uid);

	// folder <-> local-subfolder mapping:
	bool ShouldSyncFolder(const BmString& remoteFolder) const;
	BmString LocalSubPathForRemoteFolder(const BmString& remoteFolder, char delimiter) const;

	// overrides of BmRecvAccount:
	status_t Archive(BMessage* archive, bool deep = true) const;

	static const char* const AUTH_LOGIN;

	static const char* const nType;

private:
	typedef map<BmString, time_t> BmFolderUidMap;
	// per-folder UID-tracking, keyed by remote folder name:
	map<BmString, BmFolderUidMap> mFolderUIDs;
	// last known UIDVALIDITY per remote folder:
	map<BmString, BmString> mFolderUidValidity;
	// pending outbound flag-changes, keyed by remote folder name, then uid:
	map<BmString, map<BmString, uint32> > mPendingOutboundFlags;

	static const char* const MSG_FOLDER_UID_FOLDER;
	static const char* const MSG_FOLDER_UID_UID;
	static const char* const MSG_FOLDER_UID_TIME;
	static const char* const MSG_FOLDER_UIDVALIDITY_FOLDER;
	static const char* const MSG_FOLDER_UIDVALIDITY_VALUE;
	static const char* const MSG_PENDING_FLAGS_FOLDER;
	static const char* const MSG_PENDING_FLAGS_UID;
	static const char* const MSG_PENDING_FLAGS_VALUE;

	BmImapAccount();  // hide default constructor
	// Hide copy-constructor and assignment:
	BmImapAccount(const BmImapAccount&);
	BmImapAccount operator=(const BmImapAccount&);
};

#endif
