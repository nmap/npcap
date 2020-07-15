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
#include <ntddk.h>
#include <ndis.h>

/* An object pool handles allocating objects in batches to save time/allocations.
 * It is beneficial for objects which are allocated and freed frequently and
 * have a limited lifetime.
 */
typedef struct _NPF_OBJ_POOL *PNPF_OBJ_POOL;

/* Allocates an object pool.
 * param NdisHandle An NDIS handle like that returned by NdisFRegisterFilterDriver.
 * param ulObjectSize The size of object this pool will create
 * param ulIncrement Objects are allocated in multiples of this parameter
 */
_Ret_maybenull_
PNPF_OBJ_POOL NPF_AllocateObjectPool(
	_In_ NDIS_HANDLE NdisHandle,
	_In_ ULONG ulObjectSize,
	_In_ USHORT ulIncrement);

/* Frees an object pool and all associated memory.
 * All objects obtained from the pool are invalid.
 * param pPool A pointer to the pool obtained via NPF_AllocateObjectPool
 */
VOID NPF_FreeObjectPool(
	_In_ PNPF_OBJ_POOL pPool);

/* Shrinks an object pool by freeing any empty shelves (slabs) provided there
 * are enough unused slots in the existing partial slabs.
 */
VOID NPF_ShrinkObjectPool(
	_In_ PNPF_OBJ_POOL pPool);

/* Retrieve an object from the pool. The object is uninitialized and pointed to
 * by the pObject member of the returned element.
 * param pPool A pointer to the pool obtained via NPF_AllocateObjectPool
 * param bAtDispatchLevel Set TRUE if caller is at DISPATCH_LEVEL spinlock optimization
 */
_Ret_maybenull_
PVOID NPF_ObjectPoolGet(
	_In_ PNPF_OBJ_POOL pPool,
	_In_ BOOLEAN bAtDispatchLevel);

typedef VOID (*PNPF_OBJ_CLEANUP)(
	_In_ PVOID pObject);

/* Return an object to the pool. Decrements the refcount. If it is 0, the
 * object is returned to the pool. The pool is identified by the location of
 * the object's memory.
 * param pObject A pointer to an object to return
 * param CleanupFunc Optional function to perform cleanup of the object before returning it (free referenced memory, e.g.). Use NULL if no such function is needed.
 * param bAtDispatchLevel Set TRUE if caller is at DISPATCH_LEVEL spinlock optimization
 */
VOID NPF_ObjectPoolReturn(
	_In_ PVOID pObject,
	_In_opt_ PNPF_OBJ_CLEANUP CleanupFunc,
	_In_ BOOLEAN bAtDispatchLevel);

/* Reference an object from a pool. Increments the refcount.
 * param pObject A pointer to an object to reference.
 */
VOID NPF_ReferenceObject(
	_In_ PVOID pObject);
