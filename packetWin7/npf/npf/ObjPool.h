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
#ifndef _NPF_OBJ_POOL_H
#define _NPF_OBJ_POOL_H
#include <ntddk.h>
#include <ndis.h>

/* An object pool handles allocating objects in batches to save time/allocations.
 * It is beneficial for objects which are allocated and freed frequently and
 * have a limited lifetime.
 */
typedef struct _NPF_OBJ_POOL *PNPF_OBJ_POOL;

/* Context for get/return operations
 */
typedef struct _NPF_OBJ_POOL_CTX
{
	BOOLEAN bAtDispatchLevel; // Set TRUE if caller is at DISPATCH_LEVEL spinlock optimization
	PVOID pContext; // Pointer to caller-defined context. NULL if not used by InitFunc or CleanupFunc.
} NPF_OBJ_POOL_CTX, *PNPF_OBJ_POOL_CTX;

typedef _Return_type_success_(return >= 0) INT NPF_OBJ_CALLBACK_STATUS;
#define NPF_OBJ_STATUS_SUCCESS 0
/* CleanupFunc may return NPF_OBJ_STATUS_SAVED to indicate it has retained a
 * reference to the object. It MUST call NPF_ReferenceObject before returning
 * to ensure the object still has the correct refcount. It will not be returned
 * to the pool. */
#define NPF_OBJ_STATUS_SAVED 1
/* Either callback may return NPF_OBJ_STATUS_RESOURCES to indicate a failure
 * due to insufficient system resources. */
#define NPF_OBJ_STATUS_RESOURCES -1

typedef NPF_OBJ_CALLBACK_STATUS (NPF_OBJ_INIT)(
	_Inout_ PVOID pObject,
	_In_ PNPF_OBJ_POOL_CTX Context);
typedef NPF_OBJ_INIT (*PNPF_OBJ_INIT);

typedef NPF_OBJ_CALLBACK_STATUS (NPF_OBJ_CLEANUP)(
	_Inout_ PVOID pObject,
	_In_ PNPF_OBJ_POOL_CTX Context);
typedef NPF_OBJ_CLEANUP (*PNPF_OBJ_CLEANUP);

/* Allocates an object pool.
 * param NdisHandle An NDIS handle like that returned by NdisFRegisterFilterDriver.
 * param ulObjectSize The size of object this pool will create
 * param ulIncrement Objects are allocated in multiples of this parameter
 * param InitFunc Optional function to perform initialization of the object before getting it. The pool ensures the object is zeroed prior to this step.
 * param CleanupFunc Optional function to perform cleanup of the object before returning it (free referenced memory, e.g.). Use NULL if no such function is needed.
 */
_Ret_maybenull_
PNPF_OBJ_POOL NPF_AllocateObjectPool(
	_In_ NDIS_HANDLE NdisHandle,
	_In_ ULONG ulObjectSize,
	_In_ USHORT ulIncrement,
	_In_opt_ PNPF_OBJ_INIT InitFunc,
	_In_opt_ PNPF_OBJ_CLEANUP CleanupFunc);

/* Frees an object pool and all associated memory.
 * All objects obtained from the pool are invalid.
 * param pPool A pointer to the pool obtained via NPF_AllocateObjectPool
 */
VOID NPF_FreeObjectPool(
	_Inout_ PNPF_OBJ_POOL pPool);

/* Shrinks an object pool by freeing any empty shelves (slabs) provided there
 * are enough unused slots in the existing partial slabs.
 */
VOID NPF_ShrinkObjectPool(
	_In_ PNPF_OBJ_POOL pPool);

/* Retrieve an object from the pool. The object is uninitialized and pointed to
 * by the pObject member of the returned element.
 * param pPool A pointer to the pool obtained via NPF_AllocateObjectPool
 * param Context Caller-defined context.
 */
_Ret_maybenull_
PVOID NPF_ObjectPoolGet(
	_In_ PNPF_OBJ_POOL pPool,
	_In_ PNPF_OBJ_POOL_CTX Context);

/* Return an object to the pool. Decrements the refcount. If it is 0, the
 * object is returned to the pool. The pool is identified by the location of
 * the object's memory.
 * param pObject A pointer to an object to return
 * param Context Caller-defined context.
 */
VOID NPF_ObjectPoolReturn(
	_Inout_ PVOID pObject,
	_In_ PNPF_OBJ_POOL_CTX Context);

/* Reference an object from a pool. Increments the refcount.
 * param pObject A pointer to an object to reference.
 */
VOID NPF_ReferenceObject(
	_In_ PVOID pObject);

#endif // _NPF_OBJ_POOL_H
