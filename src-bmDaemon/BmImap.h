/*
 * Copyright 2002-2006, project beam (http://sourceforge.net/projects/beam).
 * All rights reserved. Distributed under the terms of the GNU GPL v2.
 *
 * Authors:
 *		Oliver Tappe <beam@hirschkaefer.de>
 */

#ifndef _BmImap_h
#define _BmImap_h

#include <memory>
#include <utility>
#include <vector>

#include <Message.h>

#include "BmDaemon.h"

#include "BmImapNestedStringList.h"
#include "BmNetJobModel.h"

using std::pair;

class BmImapAccount;

enum {
	BM_IMAP_NEEDS_PWD = 'bmIp'
};

/*------------------------------------------------------------------------------*\
	BmImapStatusFilter
		-
\*------------------------------------------------------------------------------*/
class IMPEXPBMDAEMON BmImapStatusFilter : public BmStatusFilter {
	typedef BmStatusFilter inherited;

public:
	BmImapStatusFilter(BmMemIBuf* input, BmNetJobModel* job, uint32 blockSize = 65536);

	// overrides of BmStatusFilter base:
	void Reset(BmMemIBuf* input);
	bool CheckForPositiveAnswer();

protected:
	// overrides of BmMailFilter base:
	void Filter(const char* srcBuf, uint32& srcLen, char* destBuf, uint32& destLen);

	BmNetJobModel* mJob;
	BmRingBuf mLineBuf;
	BmString mLastStatusLine;
	uint32 mLiteralCharCount;
};

/*------------------------------------------------------------------------------*\
	BmImap
		-	implements the (currently rather simplistic) IMAP-client
		-	each instance represents a single connection to a specific IMAP-account
		-	in general, each BmImap is started as a thread which exits when the
			IMAP-session has ended
\*------------------------------------------------------------------------------*/
class IMPEXPBMDAEMON BmImap : public BmNetJobModel {
	typedef BmNetJobModel inherited;

public:
	// message component definitions for additional info:
	static const char* const MSG_PWD;

	// alternate job-specifiers:
	static const int32 BM_CHECK_CAPABILITIES_JOB;
	// to find out about supported authentication types

	BmImap(const BmString& name, BmImapAccount* account);
	virtual ~BmImap();

	bool SupportsTLS() const;
	BmString SuggestAuthType() const;

	inline static int32 NextID() { return ++mId; }
	inline BmString Name() const { return ModelName(); }

	void SetTaggedMode(bool tagged);

	// overrides of netjob-model base:
	void UpdateProgress(uint32 numBytes);
	void SetupAdditionalInfo(BMessage* additionalInfo);

	// overrides of job-model base:
	bool StartJob();
	bool ShouldContinue();

	// message components used for info-msgs (communication between
	// protocol implementation and protocol-specific status filter):
	static const char* const IMSG_NEEDED_TAG;

private:
	// overrides of netjob-model base:
	void ExtractBase64(const BmString& text, BmString& base64);
	bool StartEncryption(const char* encType);

	// per-mailbox info & state, one entry per remote folder that is
	// synced for this account (populated by StateList(), filled in
	// by StateCheck(), consumed by StateCleanup()/StateRetrieve()):
	struct BmImapFolderInfo {
		BmString remoteName;
		// mailbox name as reported by the server (raw, IMAP-UTF7)
		BmString localSubPath;
		// local folder (relative to mailbox-root) this is synced into
		char delimiter;
		// server's hierarchy-delimiter for this mailbox, 0 if none
		bool noSelect;
		// true if server marked this mailbox with \Noselect
		uint32 msgCount;
		// number of msgs found on server, in this mailbox
		BmString uidValidity;
		// this mailbox's UIDVALIDITY, as reported by SELECT
		vector<BmString> uids;
		// one "uidvalidity:uid" per message, size==msgCount
		vector<uint32> flags;
		// one flag-bitmask per message, size==msgCount
		vector<uint32> sizes;
		// one rfc822.size per message, size==msgCount

		BmImapFolderInfo()
			: delimiter(0)
			, noSelect(false)
			, msgCount(0)
		{
		}
	};

	// internal functions:
	void StateConnect();
	void StateCapa();
	void StateStartTLS();
	void StateAuth();
	void StateList();
	void StateCheck();
	void StateCleanup();
	void StateRetrieve();
	void StateDisconnect();

	bool CheckOneFolder(BmImapFolderInfo& folder, uint32 folderIdx);
	bool RetrieveOneFolder(BmImapFolderInfo& folder);
	bool SelectFolder(const BmString& remoteName, uint32* existsCount = NULL,
		BmString* uidValidity = NULL);
	bool EnsureLocalFolderExists(const BmString& subPath);
	void FlushPendingOutboundFlags(const BmImapFolderInfo& folder);
	void ReconcilePulledFlags(const BmImapFolderInfo& folder, uint32 msgCount);

	BmString LocalUidToServerUid(const BmString& uid) const;
	bool DeleteMailFromServer(const BmString& uid);
	void Quit(bool WaitForAnswer = false);
	void UpdateIMAPStatus(const float, const char*, bool failed = false, bool stopped = false);
	void UpdateMailStatus(const float, const char*, int32);
	void UpdateCleanupStatus(const float, int32);
	bool CheckForPositiveAnswer(uint32 expectedSize = 4096, bool dotstuffDecoding = false,
		bool update = false, BMessage* infoMsg = NULL);
	void SendCommand(const BmString& cmd, const BmString& secret = BM_DEFAULT_STRING,
		bool dotstuffEncoding = false, bool update = false);

	static BmString FlagsToString(uint32 flags);
	static uint32 StringToFlags(const BmImapNestedStringList& flagsString);

	static int32 mId;
	// unique message ID, this is used if a
	// received message has no UID.
	BmRef<BmImapAccount> mImapAccount;
	// Info about our imap-account

	vector<BmImapFolderInfo> mFolders;
	// all remote folders considered for syncing
	enum States {
		IMAP_CONNECT = 0,
		IMAP_CAPA,
		IMAP_STARTTLS,
		IMAP_AUTH,
		IMAP_LIST,
		IMAP_CHECK,
		IMAP_CLEANUP,
		IMAP_RETRIEVE,
		IMAP_DISCONNECT,
		IMAP_DONE,
		IMAP_FINAL
	};
	uint32 mCurrMailNr;
	// nr of currently handled mail (0 if none), counted across all folders
	uint32 mNewMsgCount;
	// number of msgs to be received, summed over all folders
	uint32 mNewMsgTotalSize;
	// total-size of msgs to be received, summed over all folders
	vector<uint32> mNewMsgSizes;
	// sizes of msgs to be received, in the order they will be retrieved
	// (flattened across all folders)
	vector<pair<uint32, BmString> > mCleanupItems;
	// (folder-index, uid) pairs of msgs to be deleted from server
	BmString mSupportedAuthTypes;
	// list of auth-types the server indicates to support
	bool mServerSupportsTLS;
	// whether or not the server knows about STLS
	int32 mState;
	// current IMAP-state (refer enum below)

	bool mTaggedMode;
	// whether or not we should send/expect tagged lines
	uint32 mCurrTagNr;
	// current tag number, as required by IMAP
	BmString mCurrTag;
	// current tag identifier, (last one sent to server)

	// stuff needed for internal IMAP-state-loop:
	typedef void (BmImap::*TStateMethod)();
	struct ImapState {
		const char* text;
		TStateMethod func;
		bool skip;
		ImapState(const char* t, TStateMethod f)
			: text(t),
			  func(f),
			  skip(false)
		{
		}
	};
	static ImapState ImapStates[IMAP_FINAL];

	// Hide copy-constructor and assignment:
	BmImap(const BmImap&);
	BmImap operator=(const BmImap&);
};

#endif
