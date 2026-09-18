/*
 * Copyright 2002-2006, project beam (http://sourceforge.net/projects/beam).
 * All rights reserved. Distributed under the terms of the GNU GPL v2.
 *
 * Authors:
 *		Oliver Tappe <beam@hirschkaefer.de>
 */

#include <memory.h>
#include <stdio.h>
#include <memory>

#ifdef BEAM_FOR_BONE
#include <netinet/in.h>
#endif
#include <Directory.h>
#include <NetAddress.h>
#include <NetEndpoint.h>

#include "md5.h"

#include "regexx.hh"
#include "split.hh"
using namespace regexx;

#include "BmBasics.h"
#include "BmFilter.h"
#include "BmImap.h"
#include "BmImapAccount.h"
#include "BmLogHandler.h"
#include "BmMail.h"
#include "BmMailFolderList.h"
#include "BmNetEndpointRoster.h"
#include "BmPrefs.h"
#include "BmRosterBase.h"
#include "BmStorageUtil.h"
#include "BmUtil.h"

// standard logfile-name for this class:
#undef BM_LOGNAME
#define BM_LOGNAME Name()

/*------------------------------------------------------------------------------*\
	UnquoteImapString( token)
		-	strips surrounding double-quotes (and un-escapes \" and \\) from an
			IMAP quoted-string; returns the token unchanged if it isn't quoted.
		-	does NOT handle IMAP literals ({n}\r\n...) or modified UTF-7
			encoded mailbox names - servers using those for basic mailbox
			names (INBOX, INBOX/Foo, ...) are not expected in practice.
\*------------------------------------------------------------------------------*/
static BmString
UnquoteImapString(const BmString& token)
{
	if (token.Length() >= 2 && token.ByteAt(0) == '"' && token.ByteAt(token.Length() - 1) == '"') {
		BmString result;
		token.CopyInto(result, 1, token.Length() - 2);
		result.ReplaceAll("\\\"", "\"");
		result.ReplaceAll("\\\\", "\\");
		return result;
	}
	return token;
}

/*------------------------------------------------------------------------------*\
	QuoteImapString( str)
		-	wraps the given string in double-quotes for use as an IMAP
			quoted-string, escaping any '\' or '"' it contains.
\*------------------------------------------------------------------------------*/
static BmString
QuoteImapString(const BmString& str)
{
	BmString escaped = str;
	escaped.ReplaceAll("\\", "\\\\");
	escaped.ReplaceAll("\"", "\\\"");
	return BmString("\"") << escaped << "\"";
}

/*------------------------------------------------------------------------------*\
	CollectLocalImapRefs( localSubPath)
		-	scans the given local folder's on-disk contents directly (rather
			than going through its BmMailRefList, which may not have been
			loaded/populated yet) and builds a uid -> BmMailRef map for every
			mail found that carries a BM_MAIL_ATTR_IMAP_UID attribute.
		-	uses BmMailRef::CreateInstance(), which transparently returns the
			live, already-loaded ref if one exists (global ref-cache keyed by
			node_ref), so this never creates duplicate BmMailRef objects.
\*------------------------------------------------------------------------------*/
static map<BmString, BmRef<BmMailRef> >
CollectLocalImapRefs(const BmString& localSubPath)
{
	map<BmString, BmRef<BmMailRef> > result;
	if (!localSubPath.Length())
		return result;
	BmString fullPath = ThePrefs->GetString("MailboxPath") + "/" + localSubPath;
	BDirectory dir(fullPath.String());
	if (dir.InitCheck() != B_OK)
		return result;
	entry_ref eref;
	while (dir.GetNextRef(&eref) == B_OK) {
		BNode node(&eref);
		if (node.InitCheck() != B_OK)
			continue;
		BmString uid;
		if (!BmReadStringAttr(&node, BM_MAIL_ATTR_IMAP_UID, uid) || !uid.Length())
			continue;
		struct stat st;
		if (node.GetStat(&st) != B_OK)
			continue;
		BmRef<BmMailRef> ref = BmMailRef::CreateInstance(eref, &st);
		if (ref)
			result[uid] = ref;
	}
	return result;
}

/*------------------------------------------------------------------------------*\
	MapImapFlagsToStatus( flags, currentStatus)
		-	translates a fetched IMAP flags-bitmask into the corresponding
			local status string, for reconciling already-downloaded mail.
		-	only reconciles among the states IMAP flags can actually
			represent; returns NULL (meaning "leave unchanged") for any
			local-only status IMAP has no equivalent for.
\*------------------------------------------------------------------------------*/
static const char*
MapImapFlagsToStatus(uint32 flags, const BmString& currentStatus)
{
	if (currentStatus.Length() && currentStatus != BM_MAIL_STATUS_NEW
		&& currentStatus != BM_MAIL_STATUS_READ && currentStatus != BM_MAIL_STATUS_REPLIED
		&& currentStatus != BM_MAIL_STATUS_DRAFT)
		return NULL;
	if (flags & BM_IMAP_FLAG_ANSWERED)
		return BM_MAIL_STATUS_REPLIED;
	if (flags & BM_IMAP_FLAG_SEEN)
		return BM_MAIL_STATUS_READ;
	if (flags & BM_IMAP_FLAG_DRAFT)
		return BM_MAIL_STATUS_DRAFT;
	return BM_MAIL_STATUS_NEW;
}

/********************************************************************************\
	BmImapStatusFilter
\********************************************************************************/

/*------------------------------------------------------------------------------*\
	()
		-
\*------------------------------------------------------------------------------*/
BmImapStatusFilter::BmImapStatusFilter(BmMemIBuf* input, BmNetJobModel* job, uint32 blockSize)
	: inherited(input, blockSize),
	  mJob(job),
	  mLineBuf(1000),
	  mLiteralCharCount(0)
{
}

/*------------------------------------------------------------------------------*\
	()
		-
\*------------------------------------------------------------------------------*/
void
BmImapStatusFilter::Reset(BmMemIBuf* input)
{
	inherited::Reset(input);
	mLiteralCharCount = 0;
}

/*------------------------------------------------------------------------------*\
	()
		-
\*------------------------------------------------------------------------------*/
void
BmImapStatusFilter::Filter(const char* srcBuf, uint32& srcLen, char* destBuf, uint32& destLen)
{
	const char* src = srcBuf;
	const char* srcEnd = srcBuf + srcLen;
	char c;

	if (!mLiteralCharCount) {
		BmString tagStr;
		if (mInfoMsg)
			tagStr = mInfoMsg->FindString(BmImap::IMSG_NEEDED_TAG);

		// setup a regex-string that can decide whether or not a given line
		// is a status line.
		// IMAP defines '*' (data), '+' (continuation) or the tag as indicator,
		BmString statusRxStr = tagStr.Length() ? BmString("^(\\*|\\+|") << tagStr << ")\\s+"
											   : BmString("^(\\*|\\+)\\s+");

		Regexx rx;
		while (src < srcEnd) {
			c = *src++;
			mLineBuf << c;
			if (c == '\n') {
				// now we have a complete line in the ring buffer, we fetch it...
				mLastStatusLine = mLineBuf;
				// ...and check it's status:
				if (rx.exec(mLastStatusLine, statusRxStr)) {
					// this is a status line
					mLastStatusLine.RemoveAll("\r");
					if (mLastStatusLine.ByteAt(0) == '*' || mLastStatusLine.ByteAt(0) == '+')
						// normal status (at top of answer stream) or continuation
						// request
						mStatusText << mLastStatusLine;
					else
						// tagged status (at bottom of answer stream)
						mBottomStatusText << mLastStatusLine;
					mHaveStatus = true;
					srcLen = (uint32)(src - srcBuf);
					destLen = 0;
					// we have reached the end if no tag is expected (the answer
					// will be one line only) or if this is the tagged line:
					if (!tagStr.Length() || mLastStatusLine.ICompare(tagStr, tagStr.Length()) == 0)
						mEndReached = true;
					// check for a literal:
					if (rx.exec(mLastStatusLine, "\\{(\\d+)\\}\\s*\\n")) {
						BmString literalLen = rx.match[0].atom[0];
						mLiteralCharCount = atoi(literalLen.String());
					}
					return;
				}
				break;
			}
		}
		srcLen = (uint32)(src - srcBuf);
		destLen = 0;
		return;
	}
	uint32 size = std::min(destLen, srcLen);
	if (mLiteralCharCount) {
		if (size >= mLiteralCharCount) {
			size = mLiteralCharCount;
			mLiteralCharCount = 0;
		} else {
			mLiteralCharCount -= size;
		}
	}
	memcpy(destBuf, srcBuf, size);
	srcLen = destLen = size;
	if (mUpdate && destLen)
		mJob->UpdateProgress(destLen);
}

/*------------------------------------------------------------------------------*\
	()
		-
\*------------------------------------------------------------------------------*/
bool
BmImapStatusFilter::CheckForPositiveAnswer()
{
	BmString tagStr;
	if (mInfoMsg)
		tagStr = mInfoMsg->FindString(BmImap::IMSG_NEEDED_TAG);
	if (mLastStatusLine.Length()) {
		// a problem is indicated by "* " or "<tag> ", followed by either
		// "BAD" or "NO":
		BmString badStatusRxStr = tagStr.Length()
									  ? BmString("^(\\*|") << tagStr << ")\\s+(BAD|NO)\\b"
									  : BmString("^\\*\\s+(BAD|NO)\\b");
		Regexx rx;
		if (rx.exec(mLastStatusLine, badStatusRxStr)) {
			BmString err("Server answers: \n");
			err += mLastStatusLine;
			err.RemoveAll("\r");
			throw BM_network_error(err);
		}
	}
	return true;
}


/********************************************************************************\
	BmImap
\********************************************************************************/

// message component definitions for additional info:
const char* const BmImap::MSG_PWD = "bm:pwd";

// alternate job-specifiers:
const int32 BmImap::BM_CHECK_CAPABILITIES_JOB = 1;
// to find out about supported capabilities

const char* const BmImap::IMSG_NEEDED_TAG = "neededTag";

int32 BmImap::mId = 0;

/*------------------------------------------------------------------------------*\
	ImapStates[]
		-	array of IMAP-states, each with title and corresponding handler-method
\*------------------------------------------------------------------------------*/
BmImap::ImapState BmImap::ImapStates[BmImap::IMAP_FINAL]
	= {ImapState("connect...", &BmImap::StateConnect), ImapState("capa...", &BmImap::StateCapa),
		ImapState("starttls...", &BmImap::StateStartTLS), ImapState("auth...", &BmImap::StateAuth),
		ImapState("list...", &BmImap::StateList), ImapState("check...", &BmImap::StateCheck),
		ImapState("cleanup...", &BmImap::StateCleanup),
		ImapState("get...", &BmImap::StateRetrieve), ImapState("quit...", &BmImap::StateDisconnect),
		ImapState("done", NULL)};

/*------------------------------------------------------------------------------*\
	BmImap( info)
		-	contructor
\*------------------------------------------------------------------------------*/
BmImap::BmImap(const BmString& name, BmImapAccount* account)
	: inherited(BmString("IMAP_") << name, BM_LogRecv, new BmImapStatusFilter(NULL, this)),
	  mImapAccount(account),
	  mCurrMailNr(0),
	  mNewMsgCount(0),
	  mNewMsgTotalSize(1),
	  mServerSupportsTLS(false),
	  mState(0),
	  mTaggedMode(false),
	  mCurrTagNr(0)
{
}

/*------------------------------------------------------------------------------*\
	~BmImap()
		-	destructor
\*------------------------------------------------------------------------------*/
BmImap::~BmImap()
{
	BM_LOG_FINISH(BM_LOGNAME);
}

/*------------------------------------------------------------------------------*\
	ShouldContinue()
		-	determines whether or not the Imapper should continue to run
		-	in addition to the inherited behaviour, the Imapper should continue
			when it executes special jobs (not BM_DEFAULT_JOB), since in that
			case there are no controllers present.
\*------------------------------------------------------------------------------*/
bool
BmImap::ShouldContinue()
{
	if (mConnection && mConnection->IsStopRequested())
		return false;
	return CurrentJobSpecifier() == BM_CHECK_CAPABILITIES_JOB || inherited::ShouldContinue();
}

/*------------------------------------------------------------------------------*\
	SetupAdditionalInfo()
		-
\*------------------------------------------------------------------------------*/
void
BmImap::SetupAdditionalInfo(BMessage* additionalInfo)
{
	additionalInfo->AddString(
		BmNetEndpoint::MSG_CLIENT_CERT_NAME, mImapAccount->ClientCertificate().String());
	additionalInfo->AddString(BmNetEndpoint::MSG_SERVER_NAME, mImapAccount->Server().String());
	additionalInfo->AddString(
		BmNetEndpoint::MSG_ACCEPTED_CERT_ID, mImapAccount->AcceptedCertID().String());
}

/*------------------------------------------------------------------------------*\
	StartJob()
		-	the mainloop, steps through all IMAP-stages and calls the corresponding
			handlers
		-	returns whether or not the Imapper has completed it's job
\*------------------------------------------------------------------------------*/
bool
BmImap::StartJob()
{
	for (int32 state = IMAP_CONNECT; state < IMAP_DONE; ++state)
		ImapStates[state].skip = false;

	if (CurrentJobSpecifier() == BM_CHECK_CAPABILITIES_JOB) {
		// when checking capabilities, we skip nearly everything:
		ImapStates[IMAP_STARTTLS].skip = true;
		ImapStates[IMAP_AUTH].skip = true;
		ImapStates[IMAP_LIST].skip = true;
		ImapStates[IMAP_CHECK].skip = true;
		ImapStates[IMAP_RETRIEVE].skip = true;
	}

	int32 skipped = 0;
	for (int32 state = IMAP_CONNECT; state < IMAP_DONE; ++state) {
		if (ImapStates[state].skip)
			skipped++;
	}
	const float delta = (100.0f / float(IMAP_DONE - skipped));
	try {
		for (mState = IMAP_CONNECT; ShouldContinue() && mState < IMAP_DONE; ++mState) {
			if (ImapStates[mState].skip)
				continue;
			TStateMethod stateFunc = ImapStates[mState].func;
			UpdateIMAPStatus((mState == IMAP_CONNECT ? 0.0f : delta), NULL);
			(this->*stateFunc)();
			if (!ShouldContinue()) {
				Disconnect();
				break;
			}
		}
		if (!ShouldContinue())
			UpdateIMAPStatus(0.0, NULL, false, true);
		else
			UpdateIMAPStatus(delta, NULL);
	} catch (BM_runtime_error& err) {
		// a problem occurred, we tell the user:
		BmString errstr = err.what();
		int e;
		if (mConnection && (e = mConnection->Error()) != B_OK)
			errstr << "\nerror: " << e << ", " << mConnection->ErrorStr();
		UpdateIMAPStatus(0.0, NULL, true);
		BmString text = Name() << ":\n\n" << errstr;
		HandleError(text);
		return false;
	} catch (std::exception& err) {
		BmString errMsg;
		errMsg << err.what() << " (" << typeid(err).name() << ")";
		HandleError(errMsg);
		return false;
	} catch (...) {
		BmString errMsg;
		errMsg << "The job for account " << mImapAccount->Name()
			   << "received an unknown exception and died!";
		HandleError(errMsg);
		return false;
	}
	return true;
}

/*------------------------------------------------------------------------------*\
	UpdateIMAPStatus( delta, detailText, failed)
		-	informs the interested party about a change in the current IMAP3-state
		-	failed==true means that we only want to indicate the failure of the
			current stage (the BmString "FAILED!" will be shown)
\*------------------------------------------------------------------------------*/
void
BmImap::UpdateIMAPStatus(const float delta, const char* detailText, bool failed, bool stopped)
{
	std::auto_ptr<BMessage> msg(new BMessage(BM_JOB_UPDATE_STATE));
	msg->AddString(MSG_MODEL, Name().String());
	msg->AddString(MSG_DOMAIN, "statbar");
	msg->AddFloat(MSG_DELTA, delta);
	if (failed) {
		msg->AddString(MSG_TRAILING, (BmString(ImapStates[mState].text) << " FAILED!").String());
		msg->AddBool(MSG_FAILED, true);
	} else if (stopped)
		msg->AddString(MSG_TRAILING, (BmString(ImapStates[mState].text) << " Stopped!").String());
	else
		msg->AddString(MSG_TRAILING, ImapStates[mState].text);
	if (detailText)
		msg->AddString(MSG_LEADING, detailText);
	if (mConnection && mConnection->EncryptionIsActive())
		msg->AddBool(MSG_ENCRYPTED, true);
	TellControllers(msg.get());
}

/*------------------------------------------------------------------------------*\
	UpdateMailStatus( delta, detailText)
		- informs the interested party about the message currently dealt with
\*------------------------------------------------------------------------------*/
void
BmImap::UpdateMailStatus(const float delta, const char* detailText, int32 currMsg)
{
	BmString text;
	if (mNewMsgCount) {
		text = BmString() << currMsg << " of " << mNewMsgCount;
	} else {
		text = "none";
	}
	std::auto_ptr<BMessage> msg(new BMessage(BM_JOB_UPDATE_STATE));
	msg->AddString(MSG_MODEL, Name().String());
	msg->AddString(MSG_DOMAIN, "mailbar");
	msg->AddFloat(MSG_DELTA, delta);
	msg->AddString(MSG_LEADING, text.String());
	if (detailText)
		msg->AddString(MSG_TRAILING, detailText);
	TellControllers(msg.get());
}

/*------------------------------------------------------------------------------*\
	UpdateCleanupStatus( delta, currMsg)
		- informs the interested party about the message currently dealt with
\*------------------------------------------------------------------------------*/
void
BmImap::UpdateCleanupStatus(const float delta, int32 currMsg)
{
	BmString text;
	uint32 count = (uint32)mCleanupItems.size();
	if (count > 0) {
		text = BmString() << currMsg << " of " << count;
	} else {
		text = "none";
	}
	std::auto_ptr<BMessage> msg(new BMessage(BM_JOB_UPDATE_STATE));
	msg->AddString(MSG_MODEL, Name().String());
	msg->AddString(MSG_DOMAIN, "mailbar.cleanup");
	msg->AddFloat(MSG_DELTA, delta);
	msg->AddString(MSG_LEADING, text.String());
	TellControllers(msg.get());
}

/*------------------------------------------------------------------------------*\
	UpdateProgress( numBytes)
		-
\*------------------------------------------------------------------------------*/
void
BmImap::UpdateProgress(uint32 numBytes)
{
	float delta = (100.0f * float(numBytes)) / float(mNewMsgTotalSize ? mNewMsgTotalSize : 1);
	BmString detailText = BmString("size: ") << BytesToString(mNewMsgSizes[mCurrMailNr - 1]);
	UpdateMailStatus(delta, detailText.String(), mCurrMailNr);
}

/*------------------------------------------------------------------------------*\
	StateConnect()
		-	Initiates network-connection to IMAP-server
\*------------------------------------------------------------------------------*/
void
BmImap::StateConnect()
{
	BNetAddress addr;
	if (addr.SetTo(mImapAccount->Server().String(), mImapAccount->PortNr()) != B_OK) {
		BmString s = BmString("Could not determine address of IMAP-Server ")
					 << mImapAccount->Server();
		throw BM_network_error(s);
	}
	if (!Connect(&addr)) {
		BmString s = BmString("Could not connect to IMAP-Server ")
					 << mImapAccount->Server() << "\n\bError:\n\t" << mErrorString;
		throw BM_network_error(s);
	}
	BmString encryptionType = mImapAccount->EncryptionType();
	if (TheNetEndpointRoster->SupportsEncryption()
		&& (encryptionType.ICompare(BmImapAccount::ENCR_TLS) == 0
			|| encryptionType.ICompare(BmImapAccount::ENCR_SSL) == 0)) {
		// straight TLS or SSL, we start the encryption layer:
		if (!StartEncryption(encryptionType.String()))
			return;
	}
	// accept server greeting (either encrypted or unencrypted):
	CheckForPositiveAnswer();
}

/*------------------------------------------------------------------------------*\
	StateCapa()
		-	asks server for its capabilities
\*------------------------------------------------------------------------------*/
void
BmImap::StateCapa()
{
	SetTaggedMode(true);
	BmString cmd("CAPABILITY");
	SendCommand(cmd);
	int32 count;
	try {
		if (!CheckForPositiveAnswer())
			return;
		Regexx rx;
		if ((count = rx.exec(StatusText(), "\\bAUTH=([\\S]+)", Regexx::newline | Regexx::global))) {
			mSupportedAuthTypes.Truncate(0);
			for (int32 i = 0; i < count; ++i)
				mSupportedAuthTypes << (i ? "," : "") << rx.match[i].atom[0];
		}
		if (rx.exec(StatusText(), "\\bSTARTTLS\\b", Regexx::newline))
			mServerSupportsTLS = true;
		else
			mServerSupportsTLS = false;
	} catch (...) {
	}
}

/*------------------------------------------------------------------------------*\
	StateStartTLS()
		-
\*------------------------------------------------------------------------------*/
void
BmImap::StateStartTLS()
{
	// check if encryption via STARTTLS is requested (and possible):
	BmString encryptionType = mImapAccount->EncryptionType();

	// automatic means: use STARTTLS if available:
	if (encryptionType.ICompare(BmImapAccount::ENCR_AUTO) == 0 && mServerSupportsTLS) {
		encryptionType = BmImapAccount::ENCR_STARTTLS;
	}

	if (!TheNetEndpointRoster->SupportsEncryption()
		|| encryptionType.ICompare(BmImapAccount::ENCR_STARTTLS) != 0)
		return;

	// let's try to initiate TLS...
	SendCommand("STARTTLS");
	if (!CheckForPositiveAnswer())
		return;

	StartEncryption(BmImapAccount::ENCR_TLS);
}

/*------------------------------------------------------------------------------*\
	StartEncryption(encryptionType)
		-	extends activation of SSL/TLS encryption layer with automatic
			updating of newly accepted certificate ID.
\*------------------------------------------------------------------------------*/
bool
BmImap::StartEncryption(const char* encType)
{
	bool ok = inherited::StartEncryption(encType);
	if (ok) {
		BmString certID = mConnection->NewAcceptedCertID();
		if (certID.Length() && mImapAccount->AcceptedCertID() != certID) {
			mImapAccount->AcceptedCertID(certID);
			TheRecvAccountList->MarkAsChanged();
		}
	}
	return ok;
}

/*------------------------------------------------------------------------------*\
	ExtractBase64()
		-
\*------------------------------------------------------------------------------*/
void
BmImap::ExtractBase64(const BmString& text, BmString& base64)
{
	text.CopyInto(base64, 2, text.Length());
}

/*------------------------------------------------------------------------------*\
	StateAuth()
		-	Sends user/passwd combination and checks result
\*------------------------------------------------------------------------------*/
void
BmImap::StateAuth()
{
	BmString pwd;
	bool pwdOK = false;
	bool first = true;
	BmString authMethod = mImapAccount->AuthMethod();
	if (authMethod == BmImapAccount::AUTH_AUTO)
		authMethod = SuggestAuthType();
	if (!authMethod.Length() || authMethod == BmImapAccount::AUTH_NONE)
		return;	 // no authentication needed (*very* unlikely...)
	while (!pwdOK) {
		bool pwdGiven = false;
		if (first && mImapAccount->PwdStoredOnDisk()) {
			// use stored password:
			pwd = mImapAccount->Password();
			pwdGiven = true;
		} else if (ShouldContinue()) {
			// ask user about password:
			BmString text("Please enter password for IMAP-Account <");
			text << Name() << ">:";
			pwdGiven = BeamGuiRoster->AskUserForPwd(text, pwd);
		}
		if (!pwdGiven || !ShouldContinue()) {
			// user has cancelled, we stop
			Disconnect();
			StopJob();
			return;
		}
		first = false;
		if (authMethod == BmImapAccount::AUTH_CRAM_MD5) {
			BmString cmd = BmString("AUTHENTICATE CRAM-MD5");
			SendCommand(cmd);
			AuthCramMD5(mImapAccount->Username(), pwd);
		} else if (authMethod == BmImapAccount::AUTH_DIGEST_MD5) {
			BmString cmd = BmString("AUTHENTICATE DIGEST-MD5");
			SendCommand(cmd);
			BmString serviceUri = BmString("imap/") << mImapAccount->Server();
			AuthDigestMD5(mImapAccount->Username(), pwd, serviceUri);
		} else if (authMethod == BmImapAccount::AUTH_LOGIN) {
			// send username and password as plain text:
			BmString cmd = BmString("LOGIN ") << mImapAccount->Username() << " ";
			SendCommand(cmd, pwd);
		} else {
			throw BM_runtime_error(
				BmString("Unknown authentication type '") << authMethod << "' found!?! Skipping!");
		}
		try {
			if (CheckForPositiveAnswer())
				pwdOK = true;
			else {
				Disconnect();
				StopJob();
				return;
			}
		} catch (BM_network_error& err) {
			// let's see if the server disconnected
			Regexx rx;
			if (rx.exec(StatusText(), "^\\*\\s+BYE", Regexx::newline | Regexx::nocase)) {
				throw;
			} else {
				// it's most probably a wrong password...
				BmString errstr = err.what();
				int e;
				if (mConnection && (e = mConnection->Error()) != B_OK)
					errstr << "\nerror: " << e << ", " << mConnection->ErrorStr();
				BmString text = Name() << ":\n\n" << errstr;
				HandleError(text);
			}
		}
	}
}

/*------------------------------------------------------------------------------*\
	EnsureLocalFolderExists( subPath)
		-	makes sure a local mail-folder exists at the given sub-path
			(relative to the mailbox-root), creating it (and waiting for the
			node-monitor to pick it up) if necessary.
		-	walks subPath one segment at a time (instead of handing the whole
			multi-level path to a single create_directory() call): creating a
			child folder can implicitly create its not-yet-existing parent
			(create_directory() creates all missing intermediate
			directories), but the parent's node-monitor watch is only armed
			once its own creation has round-tripped through the node-monitor
			and been turned into a BmMailFolder - if the child is created in
			that same call, its creation happens before the parent's watch is
			active, and its creation-event is never sent (not delayed, lost
			for good). Ensuring each parent level is fully registered before
			creating the next child avoids that race, for any nesting depth.
		-	returns false if the folder could not be created/found within a
			reasonable time.
\*------------------------------------------------------------------------------*/
bool
BmImap::EnsureLocalFolderExists(const BmString& subPath)
{
	if (!subPath.Length())
		return true;

	BmString partialPath;
	int32 start = 0;
	while (start <= subPath.Length()) {
		int32 slashPos = subPath.FindFirst('/', start);
		int32 end = slashPos >= 0 ? slashPos : subPath.Length();
		BmString component;
		subPath.CopyInto(component, start, end - start);
		if (partialPath.Length())
			partialPath << "/";
		partialPath << component;

		if (!TheMailFolderList->FindMailFolderBySubPath(partialPath)) {
			BmString fullPath = ThePrefs->GetString("MailboxPath") + "/" + partialPath;
			create_directory(fullPath.String(), 0755);
			bool found = false;
			for (int i = 0; i < 100 && !found; ++i) {
				if (TheMailFolderList->FindMailFolderBySubPath(partialPath))
					found = true;
				else
					snooze(100 * 1000);
			}
			if (!found)
				return false;
		}

		if (slashPos < 0)
			break;
		start = slashPos + 1;
	}
	return true;
}

/*------------------------------------------------------------------------------*\
	SelectFolder( remoteName, existsCount, uidValidity)
		-	selects the given mailbox on the server.
		-	if existsCount/uidValidity are given, the corresponding info from
			the server's answer is extracted into them.
\*------------------------------------------------------------------------------*/
bool
BmImap::SelectFolder(const BmString& remoteName, uint32* existsCount, BmString* uidValidity)
{
	BmString cmd = BmString("SELECT ") << QuoteImapString(remoteName);
	SendCommand(cmd);
	if (!CheckForPositiveAnswer())
		return false;
	if (existsCount) {
		Regexx rx;
		if (!rx.exec(StatusText(), "\\*\\s+(\\d+)\\s+exists", Regexx::newline | Regexx::nocase))
			throw BM_network_error(BmString("answer to '") << cmd << "' has unknown format");
		BmString msgCountStr = rx.match[0].atom[0];
		int32 count = atoi(msgCountStr.String());
		*existsCount = count > 0 ? (uint32)count : 0;
	}
	if (uidValidity) {
		Regexx rx;
		if (rx.exec(StatusText(), "\\buidvalidity\\s+(\\d+)", Regexx::newline | Regexx::nocase))
			*uidValidity = rx.match[0].atom[0];
		else
			uidValidity->Truncate(0);
	}
	return true;
}

/*------------------------------------------------------------------------------*\
	FlushPendingOutboundFlags( folder)
		-	pushes any local flag-changes queued for this remote folder (via
			BmMailRef::MarkAs()/SetFlagged() on IMAP-origin mail) as UID
			STORE commands, then clears them - called right after SELECTing
			the folder, before pulling the server's current flags, so that
			our own pending changes aren't immediately overwritten by a pull
			of the (about to become stale) previous server state.
\*------------------------------------------------------------------------------*/
void
BmImap::FlushPendingOutboundFlags(const BmImapFolderInfo& folder)
{
	map<BmString, uint32> pending = mImapAccount->PendingOutboundFlags(folder.remoteName);
	map<BmString, uint32>::const_iterator iter;
	for (iter = pending.begin(); iter != pending.end(); ++iter) {
		BmString serverUID = LocalUidToServerUid(iter->first);
		BmString cmd = BmString("UID STORE ") << serverUID << " FLAGS ("
											   << FlagsToString(iter->second) << ")";
		SendCommand(cmd);
		if (!CheckForPositiveAnswer())
			throw BM_network_error(BmString("answer to '") << cmd << "' failed");
		mImapAccount->ClearPendingOutboundFlags(folder.remoteName, iter->first);
	}
}

/*------------------------------------------------------------------------------*\
	ReconcilePulledFlags( folder, msgCount)
		-	for every message in the folder that we already know about (i.e.
			NOT a newly-downloaded one - those get their initial local status
			set directly in RetrieveOneFolder()), compares the flags just
			pulled via FETCH against the corresponding local mail's current
			status/flagged state, and applies any difference locally
			(last-write-wins: whichever side changed since the last check
			simply overwrites the other, we have no other way to tell "who
			changed last" across two independent systems).
		-	only reconciles among the states IMAP flags can actually
			represent (New/Read/Replied/Draft); any other local-only status
			(Forwarded/Redirected/Sent/Pending/Error/...) is left untouched,
			since the server has no equivalent for those.
		-	applied via the "server-origin" (queueForServer=false) path, so
			this does not immediately re-queue the very change we just
			pulled as a redundant outbound push.
\*------------------------------------------------------------------------------*/
void
BmImap::ReconcilePulledFlags(const BmImapFolderInfo& folder, uint32 msgCount)
{
	bool haveLocalRefs = false;
	map<BmString, BmRef<BmMailRef> > localRefs;
	for (uint32 i = 0; i < msgCount; ++i) {
		if (!mImapAccount->IsUIDDownloaded(folder.remoteName, folder.uids[i]))
			continue;  // not downloaded yet, nothing to reconcile
		if (!haveLocalRefs) {
			localRefs = CollectLocalImapRefs(folder.localSubPath);
			haveLocalRefs = true;
		}
		map<BmString, BmRef<BmMailRef> >::const_iterator iter = localRefs.find(folder.uids[i]);
		if (iter == localRefs.end())
			continue;  // couldn't locate the local mail (e.g. moved/deleted locally)
		BmRef<BmMailRef> ref = iter->second;
		uint32 serverFlags = folder.flags[i];
		const char* newStatus = MapImapFlagsToStatus(serverFlags, ref->Status());
		if (newStatus && ref->Status() != newStatus)
			ref->MarkAs(newStatus, false);
		bool newFlagged = (serverFlags & BM_IMAP_FLAG_FLAGGED) != 0;
		if (ref->IsFlagged() != newFlagged)
			ref->SetFlagged(newFlagged, false);
	}
}

/*------------------------------------------------------------------------------*\
	StateList()
		-	discovers the mailboxes available on the server, and figures out
			which of them are to be synced (and into which local folder).
\*------------------------------------------------------------------------------*/
void
BmImap::StateList()
{
	BmString cmd("LIST \"\" \"*\"");
	SendCommand(cmd);
	if (!CheckForPositiveAnswer())
		return;

	Regexx rx;
	uint32 count = rx.exec(StatusText(),
		"^\\*\\s+LIST\\s+\\(([^)]*)\\)\\s+(\"[^\"]*\"|NIL)\\s+([^\\r\\n]+)$",
		Regexx::newline | Regexx::nocase | Regexx::global);

	mFolders.clear();
	bool haveInbox = false;
	for (uint32 i = 0; i < count; ++i) {
		BmString attrs = rx.match[i].atom[0];
		BmString delimTok = rx.match[i].atom[1];
		BmString nameTok = rx.match[i].atom[2];

		bool noSelect = attrs.IFindFirst("\\Noselect") >= 0;

		char delimiter = 0;
		if (delimTok.ICompare("NIL") != 0 && delimTok.Length() >= 3)
			delimiter = delimTok.ByteAt(1);

		BmString remoteName = UnquoteImapString(nameTok);
		if (remoteName.ICompare("INBOX") == 0)
			haveInbox = true;

		if (noSelect || !mImapAccount->ShouldSyncFolder(remoteName))
			continue;

		BmImapFolderInfo info;
		info.remoteName = remoteName;
		info.delimiter = delimiter;
		info.localSubPath = mImapAccount->LocalSubPathForRemoteFolder(remoteName, delimiter);
		mFolders.push_back(info);
	}

	if (!haveInbox) {
		// some servers omit INBOX from the LIST-answer, but we always want
		// to sync it, to stay consistent with earlier (inbox-only) versions:
		BmImapFolderInfo info;
		info.remoteName = "INBOX";
		info.localSubPath = mImapAccount->HomeFolder();
		mFolders.insert(mFolders.begin(), info);
	}

	for (uint32 i = 0; i < mFolders.size(); ++i) {
		if (!EnsureLocalFolderExists(mFolders[i].localSubPath)) {
			BM_LOG(BM_LogRecv, BmString("Could not create/find local folder '")
									<< mFolders[i].localSubPath << "' for IMAP-mailbox '"
									<< mFolders[i].remoteName << "'.");
		}
	}
}

/*------------------------------------------------------------------------------*\
	StateCheck()
		-	looks for new mail in every synced mailbox
\*------------------------------------------------------------------------------*/
void
BmImap::StateCheck()
{
	mNewMsgTotalSize = 0;
	mNewMsgCount = 0;
	mNewMsgSizes.clear();
	mCleanupItems.clear();

	for (uint32 f = 0; f < mFolders.size(); ++f) {
		if (!CheckOneFolder(mFolders[f], f))
			return;
	}

	if (mNewMsgCount == 0)
		UpdateMailStatus(0, NULL, 0);
}

/*------------------------------------------------------------------------------*\
	CheckOneFolder( folder)
		-	selects one mailbox and fetches uid/size/flags of every message in
			it, then figures out which of them are new (and thus need to be
			retrieved) and which old ones should be removed from the server.
\*------------------------------------------------------------------------------*/
bool
BmImap::CheckOneFolder(BmImapFolderInfo& folder, uint32 folderIdx)
{
	uint32 msgCount = 0;
	BmString uidValidity;
	if (!SelectFolder(folder.remoteName, &msgCount, &uidValidity))
		return false;
	folder.msgCount = msgCount;
	folder.uidValidity = uidValidity;
	mImapAccount->UidValidityForFolder(folder.remoteName, uidValidity);

	// push any locally-queued flag-changes (marked read/replied/flagged/draft
	// while offline, or since the last check) before pulling the server's
	// current state:
	FlushPendingOutboundFlags(folder);

	folder.uids.clear();
	folder.flags.clear();
	if (!msgCount)
		return true;

	BmString cmd = BmString("FETCH 1:") << msgCount << " (uid rfc822.size flags)";
	SendCommand(cmd);
	if (!CheckForPositiveAnswer())
		return false;
	Regexx rx;
	const BmString& status = StatusText();
	uint32 fetchedCount = rx.exec(status, "^\\*\\s+(\\d+)\\s+fetch\\s+(\\([^\\r\\n]*\\))",
		Regexx::newline | Regexx::nocase | Regexx::global);
	if (!fetchedCount)
		throw BM_network_error(BmString("answer to '") << cmd << "' has unknown format");
	if (fetchedCount != msgCount) {
		BM_LOG(BM_LogRecv, BmString("Strange: server indicated ")
								<< msgCount << " mails in folder " << folder.remoteName
								<< ", but FETCH received " << fetchedCount << " lines!");
		if (fetchedCount > msgCount)
			fetchedCount = msgCount;
	}

	vector<uint32> msgSizes;
	BmImapNestedStringList nestedList;
	for (uint32 i = 0; i < fetchedCount; ++i) {
		BmString nrStr = rx.match[i].atom[0];
		uint32 nr = atoi(nrStr.String());
		if (nr != i + 1)
			throw BM_network_error(
				BmString("answer to '") << cmd << "' has unexpected msg-nr. in line " << i + 1);
		const char* posInText = status.String() + rx.match[i].atom[1].start();
		if (!nestedList.Parse(posInText))
			throw BM_network_error(BmString("answer to '")
								   << cmd << "' has unparsable string list in line " << i + 1);
		uint32 listSize = (uint32)nestedList.Size();
		if (listSize % 2 != 0)
			throw BM_network_error(BmString("answer to '")
								   << cmd << "' has uneven number of items "
								   << "in string list in line " << i + 1);
		for (uint32 l = 0; l < listSize; l += 2) {
			const BmString& key = nestedList[l].Text();
			if (key.ICompare("UID") == 0) {
				// compose our uid as "uidvalidity:uid", such that we never
				// confuse UIDs, should the server decide to renumber the messages:
				BmString uid = uidValidity + ":" + nestedList[l + 1].Text();
				folder.uids.push_back(uid);
			} else if (key.ICompare("FLAGS") == 0) {
				unsigned flags = StringToFlags(nestedList[l + 1]);
				folder.flags.push_back(flags);
			} else if (key.ICompare("RFC822.SIZE") == 0) {
				const BmString& sizeStr = nestedList[l + 1].Text();
				msgSizes.push_back(atoi(sizeStr.String()));
			} else
				throw BM_network_error(BmString("answer to '")
									   << cmd << "' contains unrequested key '" << key
									   << "' in string list in line " << i + 1);
		}
		if (folder.uids.size() != i + 1)
			throw BM_network_error(
				BmString("answer to '") << cmd << "' is missing UID in line " << i + 1);
		if (folder.flags.size() != i + 1)
			throw BM_network_error(
				BmString("answer to '") << cmd << "' is missing FLAGS in line " << i + 1);
		if (msgSizes.size() != i + 1)
			throw BM_network_error(
				BmString("answer to '") << cmd << "' is missing RFC822.SIZE in line " << i + 1);
	}

	if (folder.uids.size() != msgCount)
		throw BM_network_error(BmString("answer to '") << cmd << "' does not have enough UIDs");
	if (folder.flags.size() != msgCount)
		throw BM_network_error(BmString("answer to '") << cmd << "' does not have enough FLAGS");
	if (msgSizes.size() != msgCount)
		throw BM_network_error(
			BmString("answer to '") << cmd << "' does not have enough RFC822.SIZEs");
	folder.sizes = msgSizes;

	// pull any flag-changes the server has for mail we already know about
	// (marked read/replied/flagged elsewhere, or by another mail client):
	ReconcilePulledFlags(folder, msgCount);

	// compute total size of messages that are new to us:
	for (uint32 i = 0; i < msgCount; i++) {
		if (!mImapAccount->IsUIDDownloaded(folder.remoteName, folder.uids[i])) {
			// msg is new (according to unknown UID)
			mNewMsgTotalSize += msgSizes[i];
			mNewMsgSizes.push_back(msgSizes[i]);
			mNewMsgCount++;
		} else {
			// msg is old (according to known UID), we may have to remove it now:
			BmString log;
			bool shouldBeRemoved
				= mImapAccount->ShouldUIDBeDeletedFromServer(folder.remoteName, folder.uids[i], log);
			BM_LOG2(BM_LogRecv, log);
			if (shouldBeRemoved)
				mCleanupItems.push_back(std::make_pair(folderIdx, folder.uids[i]));
		}
	}

	// remove local UIDs that are not listed on the server anymore:
	BmString removedUids = mImapAccount->AdjustToCurrentServerUids(folder.remoteName, folder.uids);
	BM_LOG(BM_LogRecv, removedUids);
	return true;
}

/*------------------------------------------------------------------------------*\
	StateCleanup()
		-	deletes all old mails from server, one mailbox at a time
\*------------------------------------------------------------------------------*/
void
BmImap::StateCleanup()
{
	uint32 count = (uint32)mCleanupItems.size();
	if (count == 0)
		return;

	uint32 done = 0;
	for (uint32 f = 0; f < mFolders.size(); ++f) {
		bool haveItemsForThisFolder = false;
		for (uint32 i = 0; i < mCleanupItems.size(); ++i) {
			if (mCleanupItems[i].first == f) {
				haveItemsForThisFolder = true;
				break;
			}
		}
		if (!haveItemsForThisFolder)
			continue;
		if (!SelectFolder(mFolders[f].remoteName))
			return;
		for (uint32 i = 0; i < mCleanupItems.size(); ++i) {
			if (mCleanupItems[i].first != f)
				continue;
			if (!DeleteMailFromServer(mCleanupItems[i].second))
				return;
			done++;
			UpdateCleanupStatus(100.0f / float(count), done);
		}
		BmString cmd("EXPUNGE");
		SendCommand(cmd);
		if (!CheckForPositiveAnswer())
			return;
	}
	mCleanupItems.clear();
	UpdateCleanupStatus(0.0, done);
}

/*------------------------------------------------------------------------------*\
	StateRetrieve()
		-	retrieves all new mails from server, one mailbox at a time
\*------------------------------------------------------------------------------*/
void
BmImap::StateRetrieve()
{
	UpdateMailStatus(-1, NULL, 0);
	mCurrMailNr = 1;
	for (uint32 f = 0; mNewMsgCount > 0 && f < mFolders.size(); ++f) {
		if (!RetrieveOneFolder(mFolders[f]))
			return;
	}
	if (mNewMsgCount)
		UpdateMailStatus(100.0, "done", mNewMsgCount);
	mCurrMailNr = 0;
}

/*------------------------------------------------------------------------------*\
	RetrieveOneFolder( folder)
		-	retrieves every new message of the given (already-checked) mailbox
			and stores it into the mapped local folder.
\*------------------------------------------------------------------------------*/
bool
BmImap::RetrieveOneFolder(BmImapFolderInfo& folder)
{
	bool haveNewInThisFolder = false;
	for (uint32 i = 0; i < folder.uids.size(); ++i) {
		if (!mImapAccount->IsUIDDownloaded(folder.remoteName, folder.uids[i])) {
			haveNewInThisFolder = true;
			break;
		}
	}
	if (!haveNewInThisFolder)
		return true;

	if (!SelectFolder(folder.remoteName))
		return false;

	bool needExpunge = false;
	for (uint32 i = 0; i < folder.uids.size(); ++i) {
		if (mImapAccount->IsUIDDownloaded(folder.remoteName, folder.uids[i])) {
			// msg is old (according to known UID), we skip it:
			continue;
		}
		// fetch current mail
		BmString serverUID = LocalUidToServerUid(folder.uids[i]);
		// use BODY.PEEK[] rather than BODY[]: per RFC 3501 6.4.5, a plain
		// BODY[<section>] fetch implicitly sets \Seen server-side as a
		// side effect - we want the server's \Seen to reflect the user's
		// actual read status (synced explicitly, see Stage 2 flag-sync),
		// not "has Beam ever downloaded this message".
		BmString cmd = BmString("UID FETCH ") << serverUID << " body.peek[]";
		SendCommand(cmd);
		time_t before = time(NULL);
		if (!CheckForPositiveAnswer(mNewMsgSizes[mCurrMailNr - 1], false, true))
			return false;
		if (mAnswerText.Length() > ThePrefs->GetInt("LogSpeedThreshold", 100 * 1024)) {
			time_t after = time(NULL);
			time_t duration = after - before > 0 ? after - before : 1;
			// log speed for mails that exceed a certain size:
			BM_LOG(BM_LogRecv, BmString("Received mail of size ")
									<< mAnswerText.Length() << " bytes in " << duration
									<< " seconds => "
									<< mAnswerText.Length() / (int32)duration / 1024.0 << "KB/s");
		}
		if ((uint32)mAnswerText.Length() != mNewMsgSizes[mCurrMailNr - 1]) {
			// as this actually happens (what the heck?) we simply
			// log it if in verbose mode:
			BM_LOG2(BM_LogRecv, BmString("Received mail has ")
									<< mAnswerText.Length()
									<< " bytes but it was announced to have "
									<< mNewMsgSizes[mCurrMailNr - 1] << " bytes.");
		}
		// now create a mail from the received data...
		BM_LOG2(BM_LogRecv, "Creating mail...");
		BmRef<BmMail> mail = new BmMail(mAnswerText, mImapAccount->Name());
		if (mail->InitCheck() != B_OK)
			return false;
		// ...set IMAP UID - TODO: Use serverUID instead?
		mail->ImapUID(folder.uids[i]);
		mail->ImapFolder(folder.remoteName);
		// ...set the message flags
		uint32 flags = folder.flags[i];
		if (flags & BM_IMAP_FLAG_ANSWERED)
			mail->MarkAs(BM_MAIL_STATUS_REPLIED);
		else if (flags & BM_IMAP_FLAG_SEEN)
			mail->MarkAs(BM_MAIL_STATUS_READ);
		else if (flags & BM_IMAP_FLAG_DRAFT)
			mail->MarkAs(BM_MAIL_STATUS_DRAFT);
		mail->SetFlagged((flags & BM_IMAP_FLAG_FLAGGED) != 0);
		// ...set destination folder according to the folder-mapping...
		mail->SetDestFolderName(folder.localSubPath);
		// ...execute mail-filters for this mail...
		BM_LOG2(BM_LogRecv, "...applying filters (in memory)...");
		mail->ApplyInboundFilters();
		// ...and store mail on disk:
		BM_LOG2(BM_LogRecv, "...storing mail...");
		if (!mail->Store())
			return false;
		BM_LOG2(BM_LogRecv, "...done");
		mImapAccount->MarkUIDAsDownloaded(folder.remoteName, folder.uids[i]);
		//	delete the retrieved message if required to do so immediately:
		BmString log;
		bool shouldBeDeleted
			= mImapAccount->ShouldUIDBeDeletedFromServer(folder.remoteName, folder.uids[i], log);
		BM_LOG2(BM_LogRecv, log);
		if (shouldBeDeleted) {
			if (!DeleteMailFromServer(folder.uids[i]))
				return false;
			needExpunge = true;
		}
		mCurrMailNr++;
	}
	if (needExpunge) {
		BmString cmd("EXPUNGE");
		SendCommand(cmd);
		if (!CheckForPositiveAnswer())
			return false;
	}
	return true;
}

/*------------------------------------------------------------------------------*\
	LocalUidToServerUid(uid)
		-	converts the local UID to the one given by server (by removing the
			uidvalidity from the local uid).
\*------------------------------------------------------------------------------*/
BmString
BmImap::LocalUidToServerUid(const BmString& uid) const
{
	BmString serverUID;
	int32 pos = uid.FindFirst(':');
	if (pos >= 0)
		serverUID.SetTo(uid.String() + pos + 1);
	else
		serverUID = uid;
	return serverUID;
}

/*------------------------------------------------------------------------------*\
	DeleteMailFromServer(uid)
		-	deletes the mail with the given UID (from the currently SELECTed
			mailbox; the caller is responsible for sending EXPUNGE afterwards)
\*------------------------------------------------------------------------------*/
bool
BmImap::DeleteMailFromServer(const BmString& uid)
{
	// we need to split off the uidvalidity from our local UID:
	BmString serverUID = LocalUidToServerUid(uid);
	BmString cmd;
	cmd = BmString("UID STORE ") << serverUID << " flags.silent (\\deleted)";
	SendCommand(cmd);
	return CheckForPositiveAnswer();
}

/*------------------------------------------------------------------------------*\
	StateDisconnect()
		-	tells the server that we are finished
\*------------------------------------------------------------------------------*/
void
BmImap::StateDisconnect()
{
	Quit(true);
}

/*------------------------------------------------------------------------------*\
	Quit( WaitForAnswer)
		-	sends a QUIT to the server, waiting for answer only
			if WaitForAnswer==true
		-	normally, we wait for an answer, just if we are shutting down
			because of an error we ignore any answer.
		-	the network-connection is always closed
\*------------------------------------------------------------------------------*/
void
BmImap::Quit(bool WaitForAnswer)
{
	BmString cmd("LOGOUT");
	try {
		SendCommand(cmd);
		if (WaitForAnswer)
			CheckForPositiveAnswer();
	} catch (...) {
	}
	Disconnect();
}

/*------------------------------------------------------------------------------*\
	SetTaggedMode()
		-	activates/deactivates the use of tags.
		-	Most of IMAP actually runs in	tagged mode, only the greetings
			isn't tagged.
\*------------------------------------------------------------------------------*/
void
BmImap::SetTaggedMode(bool tagged)
{
	mTaggedMode = tagged;
	if (!mTaggedMode)
		mCurrTag.Truncate(0);
}

/*------------------------------------------------------------------------------*\
	CheckForPositiveAnswer()
		-	adds current tag to info msg such that status filter knows what
			to look for.
\*------------------------------------------------------------------------------*/
bool
BmImap::CheckForPositiveAnswer(
	uint32 expectedSize, bool /*dotstuffDecoding*/, bool update, BMessage* infoMsg)
{
	if (!infoMsg) {
		mInfoMsg.MakeEmpty();
		infoMsg = &mInfoMsg;
	}
	infoMsg->AddString(IMSG_NEEDED_TAG, mCurrTag.String());
	return inherited::CheckForPositiveAnswer(expectedSize, false, update, infoMsg);
}

/*------------------------------------------------------------------------------*\
	SendCommand( cmd)
		-	smuggles tag into command (if required) and sends it off:
\*------------------------------------------------------------------------------*/
void
BmImap::SendCommand(const BmString& cmd, const BmString& secret, bool dotstuffEncoding, bool update)
{
	if (mTaggedMode) {
		mCurrTag = BmString("bm") << ++mCurrTagNr;
		BmString taggedCmd = mCurrTag + " " + cmd;
		inherited::SendCommand(taggedCmd, secret, dotstuffEncoding, update);
	} else
		inherited::SendCommand(cmd, secret, dotstuffEncoding, update);
}

/*------------------------------------------------------------------------------*\
	SupportsTLS()
		-	returns whether or not the server has indicated that it supports
			the STARTTLS command
\*------------------------------------------------------------------------------*/
bool
BmImap::SupportsTLS() const
{
	return mServerSupportsTLS;
}

/*------------------------------------------------------------------------------*\
	SuggestAuthType()
		-	looks at the auth-types supported by the server and selects
			the most secure of those that is supported by Beam.
\*------------------------------------------------------------------------------*/
BmString
BmImap::SuggestAuthType() const
{
	if (mSupportedAuthTypes.IFindFirst(BmImapAccount::AUTH_DIGEST_MD5) >= 0)
		return BmImapAccount::AUTH_DIGEST_MD5;
	else if (mSupportedAuthTypes.IFindFirst(BmImapAccount::AUTH_CRAM_MD5) >= 0)
		return BmImapAccount::AUTH_CRAM_MD5;
	else
		return BmImapAccount::AUTH_LOGIN;
}

BmString
BmImap::FlagsToString(uint32 flags)
{
	BmString string;
	bool first = true;
	if (flags & BM_IMAP_FLAG_SEEN) {
		string << "\\Seen";
		first = false;
	}
	if (flags & BM_IMAP_FLAG_ANSWERED) {
		if (first)
			string << "\\Answered";
		else
			string << " \\Answered";
		first = false;
	}
	if (flags & BM_IMAP_FLAG_FLAGGED) {
		if (first)
			string << "\\Flagged";
		else
			string << " \\Flagged";
		first = false;
	}
	if (flags & BM_IMAP_FLAG_DELETED) {
		if (first)
			string << "\\Deleted";
		else
			string << " \\Deleted";
		first = false;
	}
	if (flags & BM_IMAP_FLAG_DRAFT) {
		if (first)
			string << "\\Draft";
		else
			string << " \\Draft";
		first = false;
	}
	return string;
}

uint32
BmImap::StringToFlags(const BmImapNestedStringList& flagsString)
{
	uint32 flags = 0;
	for (uint32 i = 0; i < flagsString.Size(); ++i) {
		if (flagsString[i].Text() == "\\Seen")
			flags |= BM_IMAP_FLAG_SEEN;
		else if (flagsString[i].Text() == "\\Answered")
			flags |= BM_IMAP_FLAG_ANSWERED;
		else if (flagsString[i].Text() == "\\Flagged")
			flags |= BM_IMAP_FLAG_FLAGGED;
		else if (flagsString[i].Text() == "\\Deleted")
			flags |= BM_IMAP_FLAG_DELETED;
		else if (flagsString[i].Text() == "\\Draft")
			flags |= BM_IMAP_FLAG_DRAFT;
	}
	return flags;
}
