/***********************IMPORTANT NPCAP LICENSE TERMS***********************
 *                                                                         *
 * Npcap is a Windows packet sniffing driver and library and is copyright  *
 * (c) 2013-2020 by Insecure.Com LLC ("The Nmap Project").  All rights     *
 * reserved.                                                               *
 *                                                                         *
 * Even though Npcap source code is publicly available for review, it is   *
 * not open source software and may not be redistributed or incorporated   *
 * into other software without special permission from the Nmap Project.   *
 * We fund the Npcap project by selling a commercial license which allows  *
 * companies to redistribute Npcap with their products and also provides   *
 * for support, warranty, and indemnification rights.  For details on      *
 * obtaining such a license, please contact:                               *
 *                                                                         *
 * sales@nmap.com                                                          *
 *                                                                         *
 * Free and open source software producers are also welcome to contact us  *
 * for redistribution requests.  However, we normally recommend that such  *
 * authors instead ask your users to download and install Npcap            *
 * themselves.                                                             *
 *                                                                         *
 * Since the Npcap source code is available for download and review,       *
 * users sometimes contribute code patches to fix bugs or add new          *
 * features.  By sending these changes to the Nmap Project (including      *
 * through direct email or our mailing lists or submitting pull requests   *
 * through our source code repository), it is understood unless you        *
 * specify otherwise that you are offering the Nmap Project the            *
 * unlimited, non-exclusive right to reuse, modify, and relicence your     *
 * code contribution so that we may (but are not obligated to)             *
 * incorporate it into Npcap.  If you wish to specify special license      *
 * conditions or restrictions on your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This software is distributed in the hope that it will be useful, but    *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                    *
 *                                                                         *
 * Other copyright notices and attribution may appear below this license   *
 * header. We have kept those for attribution purposes, but any license    *
 * terms granted by those notices apply only to their original work, and   *
 * not to any changes made by the Nmap Project or to this entire file.     *
 *                                                                         *
 * This header summarizes a few important aspects of the Npcap license,    *
 * but is not a substitute for the full Npcap license agreement, which is  *
 * in the LICENSE file included with Npcap and also available at           *
 * https://github.com/nmap/npcap/blob/master/LICENSE.                      *
 *                                                                         *
 ***************************************************************************/
#include "ObjPool.h"
#include <limits.h>
#include "macros.h"

#pragma pack(push)
#pragma pack(4)
typedef struct _NPF_OBJ_SHELF
{
	LIST_ENTRY ShelfEntry;
	PNPF_OBJ_POOL pPool;
	ULONG ulUsed;
	SINGLE_LIST_ENTRY UnusedHead;
	KSPIN_LOCK UnusedLock;
	UCHAR pBuffer[];
} NPF_OBJ_SHELF, *PNPF_OBJ_SHELF;

/* Objects in the pool are retrieved and returned using this struct.
 * pObject is an uninitialized array of ulObjectSize bytes.
 */
typedef struct _NPF_OBJ_POOL_ELEM
{
	PNPF_OBJ_SHELF pShelf;
	SINGLE_LIST_ENTRY UnusedEntry;
	ULONG Refcount;
	UCHAR pObject[];
} NPF_OBJ_POOL_ELEM, *PNPF_OBJ_POOL_ELEM;

typedef struct _NPF_OBJ_POOL
{
	LIST_ENTRY EmptyShelfHead;
	LIST_ENTRY PartialShelfHead;
	KSPIN_LOCK ShelfLock;
	ULONG Tag;
	ULONG ulObjectSize;
	ULONG ulIncrement;
} NPF_OBJ_POOL;

#pragma pack(pop)

#define NPF_OBJECT_POOL_TAG 'TPON'

/* Ensure everything aligns to 32-bit boundaries for Interlocked functions */
#define NPF_SIZEOF_OBJ_SHELF ALIGN_UP_BY(sizeof(NPF_OBJ_SHELF), 4)
#define NPF_SIZEOF_OBJ_ELEM ALIGN_UP_BY(sizeof(NPF_OBJ_POOL_ELEM), 4)
#define NPF_OBJ_ELEM_ALLOC_SIZE(POOL) ALIGN_UP_BY(NPF_SIZEOF_OBJ_ELEM + (POOL)->ulObjectSize, 4)
#define NPF_OBJ_SHELF_ALLOC_SIZE(POOL) ROUND_TO_PAGES( NPF_SIZEOF_OBJ_SHELF + NPF_OBJ_ELEM_ALLOC_SIZE(POOL) * (POOL)->ulIncrement)
#define NPF_OBJ_ELEM_MAX_IDX(POOL) (NPF_OBJ_SHELF_ALLOC_SIZE(pPool) - NPF_SIZEOF_OBJ_SHELF)

#define OBJPOOL_IRQL_UNKNOWN FALSE
#define OBJPOOL_ACQUIRE_LOCK(_pLock, _pQueue, DispatchLevel) if (DispatchLevel) { \
	KeAcquireInStackQueuedSpinLockAtDpcLevel(_pLock, _pQueue); \
} else { \
	KeAcquireInStackQueuedSpinLock(_pLock, _pQueue); \
}
#define OBJPOOL_RELEASE_LOCK(_pLock, _pQueue, DispatchLevel) if (DispatchLevel) { \
	KeReleaseInStackQueuedSpinLockFromDpcLevel(_pQueue); \
} else { \
	KeReleaseInStackQueuedSpinLock(_pQueue); \
}

_Ret_maybenull_
PNPF_OBJ_SHELF
NPF_NewObjectShelf(
		_In_ PNPF_OBJ_POOL pPool)
{
	PNPF_OBJ_SHELF pShelf = NULL;
	PNPF_OBJ_POOL_ELEM pElem = NULL;
	ULONG i;

	pShelf = (PNPF_OBJ_SHELF) ExAllocatePoolWithTag(NonPagedPool,
			NPF_OBJ_SHELF_ALLOC_SIZE(pPool),
			pPool->Tag);
	if (pShelf == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(pShelf, NPF_OBJ_SHELF_ALLOC_SIZE(pPool));
	pShelf->pPool = pPool;

	// Buffer starts after the shelf itself
	for (i=0; i < pPool->ulIncrement; i++)
	{
		pElem = (PNPF_OBJ_POOL_ELEM) ((PUCHAR)ALIGN_UP_POINTER_BY(pShelf->pBuffer, 4) + i * NPF_OBJ_ELEM_ALLOC_SIZE(pPool));
		pElem->pShelf= pShelf;
		PushEntryList(&pShelf->UnusedHead, &pElem->UnusedEntry);
	}

	return pShelf;
}

_Use_decl_annotations_
PNPF_OBJ_POOL NPF_AllocateObjectPool(
		ULONG Tag,
		ULONG ulObjectSize,
		USHORT usIncrement)
{
	PNPF_OBJ_POOL pPool = NULL;

	pPool = (PNPF_OBJ_POOL) ExAllocatePoolWithTag(NonPagedPool,
			sizeof(NPF_OBJ_POOL),
			NPF_OBJECT_POOL_TAG);
	if (pPool == NULL)
	{
		return NULL;
	}
	RtlZeroMemory(pPool, sizeof(NPF_OBJ_POOL));

	KeInitializeSpinLock(&pPool->ShelfLock);
	InitializeListHead(&pPool->PartialShelfHead);
	InitializeListHead(&pPool->EmptyShelfHead);

	pPool->Tag = Tag;
	pPool->ulObjectSize = ulObjectSize;
	pPool->ulIncrement = usIncrement;

	// Now round up ulIncrement to the max that will fit in some pages
	ULONG max_idx = NPF_OBJ_ELEM_MAX_IDX(pPool);
	pPool->ulIncrement = max_idx / NPF_OBJ_ELEM_ALLOC_SIZE(pPool);
	// This should not have changed the max_idx
	ASSERT(max_idx == NPF_OBJ_ELEM_MAX_IDX(pPool));

	return pPool;
}

_Use_decl_annotations_
PVOID NPF_ObjectPoolGet(PNPF_OBJ_POOL pPool,
		BOOLEAN bAtDispatchLevel)
{
	KLOCK_QUEUE_HANDLE ShelfQueue;
	KLOCK_QUEUE_HANDLE UnusedQueue;
	PNPF_OBJ_POOL_ELEM pElem = NULL;
	PLIST_ENTRY pShelfEntry = NULL;
	PSINGLE_LIST_ENTRY pEntry = NULL;
	PNPF_OBJ_SHELF pShelf = NULL;
	ULONG ulUsed = 0;

	OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, bAtDispatchLevel);
	// Get the first partial shelf
	pShelfEntry = RemoveHeadList(&pPool->PartialShelfHead);

	// If there are no partial shelves, get an empty one
	if (pShelfEntry == &pPool->PartialShelfHead)
	{
		pShelfEntry = RemoveHeadList(&pPool->EmptyShelfHead);
		// If there are no empty shelves, allocate a new one
		if (pShelfEntry == &pPool->EmptyShelfHead)
		{
			pShelf = NPF_NewObjectShelf(pPool);
			// If we couldn't allocate one, bail.
			if (pShelf == NULL)
			{
				OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, bAtDispatchLevel);
				return NULL;
			}
			pShelfEntry = &pShelf->ShelfEntry;
		}
	}
	OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, bAtDispatchLevel);
	// By now, pEntry points to a shelf with at least 1 object available

	pShelf = CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry);

	OBJPOOL_ACQUIRE_LOCK(&pShelf->UnusedLock, &UnusedQueue, bAtDispatchLevel);
	ulUsed = ++pShelf->ulUsed;
	ASSERT(ulUsed > 0 && ulUsed <= pPool->ulIncrement);

	pEntry = PopEntryList(&pShelf->UnusedHead);
	if (pEntry == NULL)
	{
		// Should be impossible since all tracked shelves are partial or empty
		ASSERT(pEntry != NULL);
		// Should we decrement the used counter?
		// Hard to say, this is an impossible condition.
		OBJPOOL_RELEASE_LOCK(&pShelf->UnusedLock, &UnusedQueue, bAtDispatchLevel);
		return NULL;
	}

	// This shelf is not empty. If there are any objects left, put it into partials
	if (ulUsed < pPool->ulIncrement)
	{
		OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
		InsertTailList(&pPool->PartialShelfHead, &pShelf->ShelfEntry);
		OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
	}
	else
	{
		// This is a "full" shelf. We let it leak, trusting the return process will link it back in.
		// Let's be sure of it...
		pShelf->ShelfEntry.Flink = MM_BAD_POINTER;
		pShelf->ShelfEntry.Blink = MM_BAD_POINTER;
	}

	OBJPOOL_RELEASE_LOCK(&pShelf->UnusedLock, &UnusedQueue, bAtDispatchLevel);

	pElem = CONTAINING_RECORD(pEntry, NPF_OBJ_POOL_ELEM, UnusedEntry);

	// We zero the memory when we first allocate it, and when an object is returned.
	// RtlZeroMemory(pElem->pObject, pPool->ulObjectSize);
#if DBG
	// Let's check that condition and make sure nothing is messing with returned objects
	// (SLOW! debug only)
	for (ULONG i=0; i < pPool->ulObjectSize; i++)
	{
		ASSERT(((PUCHAR)pElem->pObject)[i] == 0);
	}
#endif

	ASSERT(pElem->Refcount == 0);
	pElem->Refcount = 1;
	return pElem->pObject;
}

_Use_decl_annotations_
VOID NPF_FreeObjectPool(PNPF_OBJ_POOL pPool)
{
	KLOCK_QUEUE_HANDLE ShelfQueue;
	PLIST_ENTRY pShelfEntry = NULL;
	PNPF_OBJ_SHELF pDeleteMe = NULL;

	OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, OBJPOOL_IRQL_UNKNOWN);

	pShelfEntry = pPool->PartialShelfHead.Flink;
	while (pShelfEntry != &pPool->PartialShelfHead)
	{
		pDeleteMe = CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry);
		pShelfEntry = pShelfEntry->Flink;
		ExFreePoolWithTag(pDeleteMe, pPool->Tag);
	}
	pShelfEntry = pPool->EmptyShelfHead.Flink;
	while (pShelfEntry != &pPool->EmptyShelfHead)
	{
		pDeleteMe = CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry);
		pShelfEntry = pShelfEntry->Flink;
		ExFreePoolWithTag(pDeleteMe, pPool->Tag);
	}
	OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, OBJPOOL_IRQL_UNKNOWN);

	ExFreePoolWithTag(pPool, NPF_OBJECT_POOL_TAG);
}

_Use_decl_annotations_
VOID NPF_ShrinkObjectPool(PNPF_OBJ_POOL pPool)
{
	KLOCK_QUEUE_HANDLE ShelfQueue;
	PLIST_ENTRY pShelfEntry = NULL;
	PLIST_ENTRY pEmptyNext = NULL;
	ULONG TotalUnused = 0;
	BOOLEAN bKeepOne = TRUE;

	if (IsListEmpty(&pPool->EmptyShelfHead))
	{
		// No empty shelves to free
		return;
	}

	OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, OBJPOOL_IRQL_UNKNOWN);

	for (pShelfEntry = pPool->PartialShelfHead.Flink; pShelfEntry != &pPool->PartialShelfHead; pShelfEntry = pShelfEntry->Flink)
	{
		TotalUnused += pPool->ulIncrement - CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry)->ulUsed;
		if (TotalUnused >= pPool->ulIncrement)
		{
			// There's at least 1 shelf's worth of unused space
			bKeepOne = FALSE;
			break;
		}
	}

	// While there are empty shelves available
	while (!IsListEmpty(&pPool->EmptyShelfHead))
	{
		// Pop one off
		pShelfEntry = RemoveHeadList(&pPool->EmptyShelfHead);
		// If we need to keep one and this was the last one,
		if (bKeepOne && IsListEmpty(&pPool->EmptyShelfHead))
		{
			// Put it back and quit
			InsertHeadList(&pPool->EmptyShelfHead, pShelfEntry);
			break;
		}
		ExFreePoolWithTag(
				CONTAINING_RECORD(pShelfEntry, NPF_OBJ_SHELF, ShelfEntry),
				pPool->Tag);
	}

	OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, OBJPOOL_IRQL_UNKNOWN);
}

_Use_decl_annotations_
BOOLEAN NPF_ObjectPoolReturn(
		PVOID pObject,
		BOOLEAN bAtDispatchLevel)
{
	ASSERT(pObject);
	KLOCK_QUEUE_HANDLE ShelfQueue;
	KLOCK_QUEUE_HANDLE UnusedQueue;
	PNPF_OBJ_SHELF pShelf = NULL;
	PNPF_OBJ_POOL pPool = NULL;
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);
	ULONG refcount = NpfInterlockedDecrement(&pElem->Refcount);
	ASSERT(refcount < ULONG_MAX);

	if (refcount == 0)
	{
		pShelf = pElem->pShelf;
		pPool = pShelf->pPool;

		// Zero this now to ensure unused objects are zeroed when retrieved
		// Doing it this way helps spot bugs by invalidating pointers in the old object
		RtlZeroMemory(pElem->pObject, pPool->ulObjectSize);

		OBJPOOL_ACQUIRE_LOCK(&pShelf->UnusedLock, &UnusedQueue, bAtDispatchLevel);

		refcount = --pShelf->ulUsed;
		ASSERT(refcount < pPool->ulIncrement);

		PushEntryList(&pShelf->UnusedHead, &pElem->UnusedEntry);

		// We only need to acquire ShelfLock in these 2 cases.
		if (refcount == 0)
		{
			// Empty shelf. Move it to the other list.
			OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
			RemoveEntryList(&pShelf->ShelfEntry);
			InsertTailList(&pPool->EmptyShelfHead, &pShelf->ShelfEntry);
			OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
		}
		else if (refcount == pPool->ulIncrement - 1)
		{
			// This shelf was full and now it's partial. Link it in.
			ASSERT(pShelf->ShelfEntry.Flink == MM_BAD_POINTER);
			ASSERT(pShelf->ShelfEntry.Blink == MM_BAD_POINTER);
			OBJPOOL_ACQUIRE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
			InsertTailList(&pPool->PartialShelfHead, &pShelf->ShelfEntry);
			OBJPOOL_RELEASE_LOCK(&pPool->ShelfLock, &ShelfQueue, TRUE);
		}
		OBJPOOL_RELEASE_LOCK(&pShelf->UnusedLock, &UnusedQueue, bAtDispatchLevel);
		return TRUE;
	}
	return FALSE;
}

_Use_decl_annotations_
VOID NPF_ReferenceObject(PVOID pObject)
{
	ASSERT(pObject);
	PNPF_OBJ_POOL_ELEM pElem = CONTAINING_RECORD(pObject, NPF_OBJ_POOL_ELEM, pObject);

	InterlockedIncrement(&pElem->Refcount);
	// If we get this many, we have an obvious bug.
	ASSERT(pElem->Refcount < ULONG_MAX);
}
