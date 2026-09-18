/*
 * Copyright 2002-2006, project beam (http://sourceforge.net/projects/beam).
 * All rights reserved. Distributed under the terms of the GNU GPL v2.
 *
 * Authors:
 *		Oliver Tappe <beam@hirschkaefer.de>
 */

#include <Application.h>
#include <ByteOrder.h>
#include <File.h>
#include <Message.h>
#include <MessageRunner.h>

#include "regexx.hh"
using namespace regexx;

#include "BmBasics.h"
#include "BmIdentity.h"
#include "BmImapAccount.h"
#include "BmLogHandler.h"
#include "BmMailFolder.h"
#include "BmRosterBase.h"
#include "BmUtil.h"

/********************************************************************************\
	BmImapAccount
\********************************************************************************/

const char* const BmImapAccount::AUTH_LOGIN = "LOGIN";

const char* const BmImapAccount::nType = "IMAP";

const char* const BmImapAccount::MSG_FOLDER_UID_FOLDER = "bm:ifuidf";
const char* const BmImapAccount::MSG_FOLDER_UID_UID = "bm:ifuidu";
const char* const BmImapAccount::MSG_FOLDER_UID_TIME = "bm:ifuidt";
const char* const BmImapAccount::MSG_FOLDER_UIDVALIDITY_FOLDER = "bm:ifuidvf";
const char* const BmImapAccount::MSG_FOLDER_UIDVALIDITY_VALUE = "bm:ifuidvv";
const char* const BmImapAccount::MSG_PENDING_FLAGS_FOLDER = "bm:ipff";
const char* const BmImapAccount::MSG_PENDING_FLAGS_UID = "bm:ipfu";
const char* const BmImapAccount::MSG_PENDING_FLAGS_VALUE = "bm:ipfv";

/*------------------------------------------------------------------------------*\
	BmImapAccount()
		-	c'tor
\*------------------------------------------------------------------------------*/
BmImapAccount::BmImapAccount(const char* name, BmRecvAccountList* model)
	: inherited(name, model)
{
	mPortNr = 143;
	mPortNrString = "143";
	SetupIntervalRunner();
}

/*------------------------------------------------------------------------------*\
	BmImapAccount( archive)
		-	c'tor
		-	constructs a BmImapAccount from a BMessage
\*------------------------------------------------------------------------------*/
BmImapAccount::BmImapAccount(BMessage* archive, BmRecvAccountList* model)
	: inherited(archive, model)
{
	SetupIntervalRunner();

	const char* folderName;
	const char* uid;
	int64 timeDownloaded;
	for (int32 i = 0; archive->FindString(MSG_FOLDER_UID_FOLDER, i, &folderName) == B_OK
					  && archive->FindString(MSG_FOLDER_UID_UID, i, &uid) == B_OK
					  && archive->FindInt64(MSG_FOLDER_UID_TIME, i, &timeDownloaded) == B_OK;
		 ++i) {
		mFolderUIDs[folderName][uid] = (time_t)timeDownloaded;
	}

	const char* uidValidity;
	for (int32 i = 0; archive->FindString(MSG_FOLDER_UIDVALIDITY_FOLDER, i, &folderName) == B_OK
					  && archive->FindString(MSG_FOLDER_UIDVALIDITY_VALUE, i, &uidValidity)
							 == B_OK;
		 ++i) {
		mFolderUidValidity[folderName] = uidValidity;
	}

	const char* pendingUid;
	int32 pendingFlags;
	for (int32 i = 0; archive->FindString(MSG_PENDING_FLAGS_FOLDER, i, &folderName) == B_OK
					  && archive->FindString(MSG_PENDING_FLAGS_UID, i, &pendingUid) == B_OK
					  && archive->FindInt32(MSG_PENDING_FLAGS_VALUE, i, &pendingFlags) == B_OK;
		 ++i) {
		mPendingOutboundFlags[folderName][pendingUid] = (uint32)pendingFlags;
	}
}

/*------------------------------------------------------------------------------*\
	Archive( archive, deep)
		-	adds per-folder UID-tracking info on top of the fields already
			archived by BmRecvAccount.
\*------------------------------------------------------------------------------*/
status_t
BmImapAccount::Archive(BMessage* archive, bool deep) const
{
	status_t ret = inherited::Archive(archive, deep);

	map<BmString, BmFolderUidMap>::const_iterator folderIter;
	BmFolderUidMap::const_iterator uidIter;
	for (folderIter = mFolderUIDs.begin(); ret == B_OK && folderIter != mFolderUIDs.end();
		 ++folderIter) {
		for (uidIter = folderIter->second.begin();
			 ret == B_OK && uidIter != folderIter->second.end(); ++uidIter) {
			ret = archive->AddString(MSG_FOLDER_UID_FOLDER, folderIter->first.String())
				  || archive->AddString(MSG_FOLDER_UID_UID, uidIter->first.String())
				  || archive->AddInt64(MSG_FOLDER_UID_TIME, (int64)uidIter->second);
		}
	}

	map<BmString, BmString>::const_iterator validityIter;
	for (validityIter = mFolderUidValidity.begin();
		 ret == B_OK && validityIter != mFolderUidValidity.end(); ++validityIter) {
		ret = archive->AddString(MSG_FOLDER_UIDVALIDITY_FOLDER, validityIter->first.String())
			  || archive->AddString(MSG_FOLDER_UIDVALIDITY_VALUE, validityIter->second.String());
	}

	map<BmString, map<BmString, uint32> >::const_iterator pendingFolderIter;
	map<BmString, uint32>::const_iterator pendingUidIter;
	for (pendingFolderIter = mPendingOutboundFlags.begin();
		 ret == B_OK && pendingFolderIter != mPendingOutboundFlags.end(); ++pendingFolderIter) {
		for (pendingUidIter = pendingFolderIter->second.begin();
			 ret == B_OK && pendingUidIter != pendingFolderIter->second.end(); ++pendingUidIter) {
			ret = archive->AddString(MSG_PENDING_FLAGS_FOLDER, pendingFolderIter->first.String())
				  || archive->AddString(MSG_PENDING_FLAGS_UID, pendingUidIter->first.String())
				  || archive->AddInt32(MSG_PENDING_FLAGS_VALUE, (int32)pendingUidIter->second);
		}
	}

	return ret;
}

/*------------------------------------------------------------------------------*\
	IsUIDDownloaded( remoteFolder, uid)
		-	checks if a mail with the given uid has already been downloaded
			from the given remote folder
\*------------------------------------------------------------------------------*/
bool
BmImapAccount::IsUIDDownloaded(const BmString& remoteFolder, const BmString& uid) const
{
	map<BmString, BmFolderUidMap>::const_iterator folderIter = mFolderUIDs.find(remoteFolder);
	if (folderIter == mFolderUIDs.end())
		return false;
	return folderIter->second.find(uid) != folderIter->second.end();
}

/*------------------------------------------------------------------------------*\
	MarkUIDAsDownloaded( remoteFolder, uid)
		-	marks the given uid (within the given remote folder) as downloaded
\*------------------------------------------------------------------------------*/
void
BmImapAccount::MarkUIDAsDownloaded(const BmString& remoteFolder, const BmString& uid)
{
	mFolderUIDs[remoteFolder][uid] = time(NULL);
	TheRecvAccountList->MarkAsChanged();
}

/*------------------------------------------------------------------------------*\
	ShouldUIDBeDeletedFromServer( remoteFolder, uid, logOutput)
		-	checks if a mail with the given uid (within the given remote folder)
			should be deleted from the server now
\*------------------------------------------------------------------------------*/
bool
BmImapAccount::ShouldUIDBeDeletedFromServer(
	const BmString& remoteFolder, const BmString& uid, BmString& logOutput) const
{
	if (!DeleteMailFromServer()) {
		logOutput = BmString("Leaving mail with UID ")
					<< uid << " in folder " << remoteFolder << " on server\n"
					<< "since user has told us to leave all mails on server.";
		return false;
	}
	map<BmString, BmFolderUidMap>::const_iterator folderIter = mFolderUIDs.find(remoteFolder);
	if (folderIter == mFolderUIDs.end())
		return false;
	BmFolderUidMap::const_iterator uidIter = folderIter->second.find(uid);
	if (uidIter == folderIter->second.end())
		// hm, UID is unknown locally, we better leave it
		return false;

	time_t timeDownloaded = uidIter->second;
	time_t expirationTime = timeDownloaded + 60 * 60 * 24 * DeleteMailDelay();
	time_t now = time(NULL);
	if (expirationTime <= now) {
		logOutput = BmString("Removing mail with UID ")
					<< uid << " in folder " << remoteFolder << " from server\n"
					<< "since it has been downloaded on " << TimeToString(timeDownloaded)
					<< ",\nit's expiration time is " << TimeToString(expirationTime)
					<< "\nand now it is " << TimeToString(now);
		return true;
	}
	logOutput = BmString("Leaving mail with UID ")
				<< uid << " in folder " << remoteFolder << " on server\n"
				<< "since it has been downloaded on " << TimeToString(timeDownloaded)
				<< ",\nit's expiration time is " << TimeToString(expirationTime)
				<< "\nand now it is " << TimeToString(now);
	return false;
}

/*------------------------------------------------------------------------------*\
	AdjustToCurrentServerUids( remoteFolder, serverUids)
		-	removes all UIDs of the given remote folder unless they are
			contained in the given vector, i.e. throws away old UIDs that
			no longer exist on server (within that folder).
\*------------------------------------------------------------------------------*/
BmString
BmImapAccount::AdjustToCurrentServerUids(
	const BmString& remoteFolder, const vector<BmString>& serverUids)
{
	BmString removedInfo;
	BmFolderUidMap& uidMap = mFolderUIDs[remoteFolder];
	BmFolderUidMap::iterator iter;
	BmFolderUidMap::iterator curr;
	for (iter = uidMap.begin(); iter != uidMap.end();) {
		curr = iter++;
		bool found = false;
		for (uint32 s = 0; s < serverUids.size(); ++s) {
			if (curr->first.Compare(serverUids[s]) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			removedInfo << "Removed local UID " << curr->first << " in folder " << remoteFolder
						<< " since it is not listed by the server anymore.\n";
			uidMap.erase(curr);
		}
	}
	if (removedInfo.Length())
		TheRecvAccountList->MarkAsChanged();
	return removedInfo;
}

/*------------------------------------------------------------------------------*\
	UidValidityForFolder( remoteFolder)
		-	returns the last known UIDVALIDITY for the given remote folder
			(empty string if unknown)
\*------------------------------------------------------------------------------*/
BmString
BmImapAccount::UidValidityForFolder(const BmString& remoteFolder) const
{
	map<BmString, BmString>::const_iterator iter = mFolderUidValidity.find(remoteFolder);
	return iter != mFolderUidValidity.end() ? iter->second : BmString();
}

/*------------------------------------------------------------------------------*\
	UidValidityForFolder( remoteFolder, uidValidity)
		-	stores the current UIDVALIDITY for the given remote folder.
		-	if the UIDVALIDITY has changed since last time, all UIDs we know
			about for that folder are dropped, since the server is now free
			to reuse UIDs we had already associated with different messages
			(RFC 3501, 2.3.1.1).
\*------------------------------------------------------------------------------*/
void
BmImapAccount::UidValidityForFolder(const BmString& remoteFolder, const BmString& uidValidity)
{
	BmString& stored = mFolderUidValidity[remoteFolder];
	if (stored.Length() && stored != uidValidity) {
		BM_LOG(BM_LogRecv, BmString("UIDVALIDITY of folder ")
								<< remoteFolder << " changed from " << stored << " to "
								<< uidValidity << ", dropping known UIDs for that folder.");
		mFolderUIDs[remoteFolder].clear();
		// any flag-changes queued against the old (now meaningless) UIDs
		// can no longer be applied:
		mPendingOutboundFlags[remoteFolder].clear();
	}
	stored = uidValidity;
	TheRecvAccountList->MarkAsChanged();
}

/*------------------------------------------------------------------------------*\
	QueueOutboundFlags( remoteFolder, uid, flags)
		-	queues a local flag-change to be pushed to the server (as a
			UID STORE) at the start of the next check for that folder.
\*------------------------------------------------------------------------------*/
void
BmImapAccount::QueueOutboundFlags(const BmString& remoteFolder, const BmString& uid, uint32 flags)
{
	if (!remoteFolder.Length() || !uid.Length())
		return;
	mPendingOutboundFlags[remoteFolder][uid] = flags;
	TheRecvAccountList->MarkAsChanged();
}

/*------------------------------------------------------------------------------*\
	PendingOutboundFlags( remoteFolder)
		-	returns (a copy of) all pending outbound flag-changes queued for
			the given remote folder, keyed by uid.
\*------------------------------------------------------------------------------*/
map<BmString, uint32>
BmImapAccount::PendingOutboundFlags(const BmString& remoteFolder) const
{
	map<BmString, map<BmString, uint32> >::const_iterator iter
		= mPendingOutboundFlags.find(remoteFolder);
	if (iter == mPendingOutboundFlags.end())
		return map<BmString, uint32>();
	return iter->second;
}

/*------------------------------------------------------------------------------*\
	ClearPendingOutboundFlags( remoteFolder, uid)
		-	removes a single uid's pending outbound flag-change, once it has
			been successfully pushed to the server.
\*------------------------------------------------------------------------------*/
void
BmImapAccount::ClearPendingOutboundFlags(const BmString& remoteFolder, const BmString& uid)
{
	map<BmString, map<BmString, uint32> >::iterator folderIter
		= mPendingOutboundFlags.find(remoteFolder);
	if (folderIter == mPendingOutboundFlags.end())
		return;
	folderIter->second.erase(uid);
	TheRecvAccountList->MarkAsChanged();
}

/*------------------------------------------------------------------------------*\
	ShouldSyncFolder( remoteFolder)
		-	decides whether the given remote folder should be synced at all.
		-	currently all selectable folders reported by the server are
			synced; per-folder subscription/selection is a candidate for a
			future extension (would need a settings UI).
\*------------------------------------------------------------------------------*/
bool
BmImapAccount::ShouldSyncFolder(const BmString& /*remoteFolder*/) const
{
	return true;
}

/*------------------------------------------------------------------------------*\
	LocalSubPathForRemoteFolder( remoteFolder, delimiter)
		-	maps a remote IMAP mailbox name to the sub-path (relative to this
			account's HomeFolder()) it should be synced into locally.
		-	INBOX is mapped onto the HomeFolder() itself, all other mailboxes
			are mapped onto same-named sub-folders of the HomeFolder(),
			translating the server's hierarchy-delimiter into '/'.
		-	path components that could escape the mailbox-tree (empty
			components, ".", "..") are dropped, in order to guard against a
			misbehaving/malicious server.
\*------------------------------------------------------------------------------*/
BmString
BmImapAccount::LocalSubPathForRemoteFolder(const BmString& remoteFolder, char delimiter) const
{
	if (remoteFolder.ICompare("INBOX") == 0)
		return HomeFolder();

	BmString relPath = remoteFolder;
	if (delimiter && delimiter != '/')
		relPath.ReplaceAll(delimiter, '/');

	BmString safePath;
	int32 start = 0;
	int32 len = relPath.Length();
	while (start <= len) {
		int32 slashPos = relPath.FindFirst('/', start);
		int32 end = slashPos >= 0 ? slashPos : len;
		BmString component;
		relPath.CopyInto(component, start, end - start);
		if (component.Length() && component != "." && component != "..") {
			if (safePath.Length())
				safePath << "/";
			safePath << component;
		}
		if (slashPos < 0)
			break;
		start = slashPos + 1;
	}

	BmString subPath = HomeFolder();
	if (safePath.Length()) {
		if (subPath.Length())
			subPath << "/";
		subPath << safePath;
	}
	return subPath;
}

/*------------------------------------------------------------------------------*\
	~BmImapAccount()
		-	d'tor
\*------------------------------------------------------------------------------*/
BmImapAccount::~BmImapAccount() {}

/*------------------------------------------------------------------------------*\
	GetSupportedAuthTypes()
		-
\*------------------------------------------------------------------------------*/
void
BmImapAccount::GetSupportedAuthTypes(vector<BmString>& outList) const
{
	outList.push_back(AUTH_AUTO);
	outList.push_back(AUTH_CRAM_MD5);
	outList.push_back(AUTH_DIGEST_MD5);
	outList.push_back(AUTH_LOGIN);
	outList.push_back(AUTH_NONE);
}
