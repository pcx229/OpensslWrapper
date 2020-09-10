
#ifndef SHARED_CONTEXT
#define SHARED_CONTEXT

#include "openssl/bn.h"
#include "openssl/evp.h"

#include <thread>
#include <mutex>
#include <map>
#include <vector>
#include <list>
#include <memory>
#include <iostream>
using namespace std;

#include "openssl/bn.h"
#include "openssl/evp.h"

namespace crypto {

	/**
	 * 		Overview
	 * 		--------
	 * SharedContext is a memory management system made to reduce
	 * the amount of memory the program need to take when dealing with
	 * one of openssl libraries class wrappers.
	 * since memory allocation can be expensive the theory is that many classes
	 * on the same thread will share the same context for the same data type
	 * usage in as many places.
	 *
	 *                       +--------+     |
	 *                  +--- | user A |     |
	 *  +---------+     |    +--------+     |
	 *  | context | <---+                   |  Thread A
	 *  | Type BN |     |                   |
	 *  +---------+     |                   |
	 *                  |       +--------+  |
	 *                  +------ | user B |  |
	 *                          +--------+  |
	 *
	 *                       +--------+     |
	 *                  +--- | user C |     |
	 *  +---------+     |    +--------+     |
	 *  | context | <---+                   |  Thread B
	 *  | Type BN |     |                   |
	 *  +---------+     |                   |
	 *                  |       +--------+  |
	 *                  +------ | user D |  |
	 *                          +--------+  |
	 *
	 * **its not always possible** giving for the following scenario:
	 * 	if one function calls another function that uses
	 * 	the same shared context, the context when returning from
	 * 	the second function may contain different data then what
	 * 	was before the call. it can be a serious problem when the context
	 * 	used for a chain of commands for example:
	 * 	EVP_DigestInit - EVP_DigestUpdate - EVP_DigestFinal
	 * 	the context is needed throughout the operation, any changes
	 * 	to the context in the middle will give corrupted result.
	 *
	 *	but for a **single operation** use case this method require less memory.
	 *	there are many single operation function in the openssl library that can
	 * 	the program uses and can benefit from this approach.
	 *
	 *
	 *		Usage
	 *		-----
	 *  XXX_SINGLE_USE_SHARED_CONTEXT ctx = XXX_SHARED_CONTEXT_MANAGER::getInstance();
	 *	the context data is fixed, ctx is a shared_ptr so getting the
	 *	actual data can be done by *ctx
	 *	for example: BN_mul(r, a, b, *ctx) - no need to free in the end.
	 *
	 */
	template<typename Data, Data *(*allocData)(), void (*freeData)(Data *)>
	class SharedContext final {

			mutex mt;
			map<thread::id, shared_ptr<Data> > threads_context;

			class context_deleter {

					SharedContext *manager;
					thread::id tid;

				public:
					context_deleter(SharedContext *manager, thread::id tid) : manager(manager), tid(tid) {}
					void operator()(Data* p) {
						lock_guard<mutex> lock(manager->mt);
						manager->threads_context.erase(tid);
						freeData(p);
					}
			};

			shared_ptr<Data> getThreadContext(thread::id tid) {
				auto it = threads_context.find(tid), end = threads_context.end();
				if(it != end) {
					return it->second;
				}
				return (threads_context[tid] = shared_ptr<Data>(allocData(), context_deleter(this, tid)));
			}
			shared_ptr<Data> getMyThreadContext() {
				return getThreadContext(this_thread::get_id());
			}

			SharedContext() = default;
			SharedContext(const SharedContext &) = delete;
			SharedContext &operator=(const SharedContext &) = delete;

		public:

			static shared_ptr<Data> getInstance() {
				static SharedContext sc;
				lock_guard<mutex> lock(sc.mt);
				return sc.getMyThreadContext();
			}
	};

	typedef SharedContext<BN_CTX, BN_CTX_new, BN_CTX_free> BN_SINGLE_USE_SHARED_CONTEXT_MANAGER;
	typedef shared_ptr<BN_CTX> BN_SINGLE_USE_SHARED_CONTEXT;

	typedef SharedContext<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free> EVP_MD_SINGLE_USE_SHARED_CONTEXT_MANAGER;
	typedef shared_ptr<EVP_MD_CTX> EVP_MD_SINGLE_USE_SHARED_CONTEXT;

	/**
	 * 		Overview
	 * 		--------
	 *	SharedContext_ex is an advanced memory management system
	 *	made to reduce the amount of memory the program need to take when
	 *	dealing with one of openssl libraries class wrappers.
	 *	it can handle a task that is not possible with the
	 *	standard SharedContext system(or more accurately should be avoided),
	 *	a chain of commands usage for a context.
	 *	in contrast to the standard system that keep a fixed pointer to
	 *  the data, the pointer and data is now being initialized only when
	 *  being used explicitly(by * operator or by converter XXX* operator).
	 *
	 * 		Diagrams
	 * 		--------
	 *                       +--------+     |
	 *                  +--- | user A |     |
	 *  +---------+     |    +--------+     |
	 *  | context | <---+                   |
	 *  | Type BN |        lock mode only   |
	 *  |  Lockd  |        one user owns    |
	 *  +---------+          the context    |
	 *                                      |
	 *                      +--------+      |  Thread A
	 *                  +-- | user B |      |
	 *  +---------+     |   +--------+      |
	 *  | context | <---+                   |
	 *  | Type BN |     |                   |
	 *  +---------+     |      +--------+   |
	 *                  +----- | user C |   |
	 *                         +--------+   |
	 *                                      |
	 *
	 * 	get request --> is lock on current context? - yes -> get locked context
	 * 							 |
	 * 						     no
	 * 						     +->  what was the previous thread the context used?
	 * 						                             |
	 * 						         different thread  <-+-> this thread
	 * 						                 |                    |
	 * 						                 |                    +-> get thread free context
	 * 						                 |
	 *                                       +-> migrate to this thread
	 *                                           get thread free context
	 *
	 *  lock request --> what was the previous thread current context used?
	 * 						                        |
	 * 						    different thread  <-+-> this thread
	 * 						    		|					|
	 * 						    		+-> get request		|
	 * 						    		         |          |
	 * 						    		         +--------->|
	 * 						    		         			|
	 * 						    		                    +-> block thread free context
	 *
	 *		Usage
	 *		-----
	 *	XXX_SHARED_CONTEXT ctx;
	 *	// getting the actual data can be done by just ctx when assigning
	 *	// to XXX* data type by converter or *ctx
	 *
	 *	- single command usage example:
	 *	BN_mul(r, a, b, ctx);
	 *
	 *	- chain commands usage example:
	 *	ctx.lock(); // prevent others from using this context
	 *	EVP_DigestInit_ex(ctx, md, NULL)
	 *	// getting another/or using existing instance of this thread
	 *	// context type in between is now possible without damaging
	 *	// this context
	 *	EVP_DigestUpdate(ctx, data, size)
	 *	EVP_DigestFinal_ex(ctx, md_value, &md_len)
	 *	ctx.unlock();
	 */

	template<typename Data, Data *(*allocData)(), void (*freeData)(Data *), int (*copyData)(Data*, const Data*)>
	class SharedContext_ex final {

		public:

			struct context {

				Data *ctx;
				int number_holders;
				int my_id;

				context(int my_id)
					: ctx(nullptr), number_holders(0), my_id(my_id) { }
				~context() {
					if(ctx != nullptr) {
						freeData(ctx);
					}
				}
				void copy(const context *other) {
					if(other->ctx != nullptr) {
						copyData(ctx, other->ctx);
					}
				}
				Data *get() {
					if(ctx == nullptr) {
						if((ctx = allocData()) == NULL) {
							throw runtime_error("context allocation failed");
						}
					}
					return ctx;
				}
			};

			class temporary {

				SharedContext_ex *manager;
				context *current;
				bool locked;

					void init(const temporary &other) {
						lock_guard<mutex> lock(other.manager->mt);
						manager = other.manager;
						locked = other.locked;
						if(locked) {
							current = manager->getLockedContext(nullptr);
							if(copyData != nullptr) {
								current->copy(other.current);
							} else {
								//throw runtime_error("ShareContext error: no copy method provided");
							}
						} else {
							current = manager->getFreeContext(nullptr);
						}
					}

				public:

					temporary() {
						init(SharedContext_ex<Data, allocData, freeData, copyData>::getInstance().getMyThreadTemporary());
					}

					temporary(SharedContext_ex *manager, context *current)
						: manager(manager), current(current), locked(false) {
						manager->useContext(current);
					}

					temporary(const temporary &other) {
						init(other);
					}

					temporary &operator=(const temporary &other) {
						lock_guard<mutex> lock(manager->mt);
						if(other.locked) {
							if(!locked) {
								current = manager->getLockedContext(current);
								locked = true;
							}
							if(copyData != nullptr) {
								current->copy(other.current);
							} else {
								//throw runtime_error("ShareContext error: no copy method provided");
							}
						}
						return *this;
					}

					~temporary() {
						lock_guard<mutex> lock(manager->mt);
						if(locked) {
							current = manager->unlockContext(current);
						}
						manager->deleteFreeContext(current);
					}

					// determine state

					bool operator!() const {
						return !((bool)*this);
					}

					operator bool() const {
						return (current != nullptr && manager != nullptr);
					}

					// data access

					Data* getContext() {
						lock_guard<mutex> lock(manager->mt);
						// if locked no one can access that context from anywhere
						// so even is the context is sign to another thread on another
						Data *dctx;
						if(locked) {
							dctx = current->get();
						} else {
							dctx = (current = manager->getFreeContext(current))->get();
						}
						return dctx;
					}

					Data* getContext() const {
						return const_cast<temporary*>(this)->getContext();
					}

					Data *operator*() const {
						return getContext();
					}

					operator Data*() const {
						return getContext();
					}

					// locker

					void lock() {
						lock_guard<mutex> lock(manager->mt);
						if(!locked) {
							locked = true;
							current = manager->getLockedContext(current);
						}
					}

					void lock() const {
						const_cast<temporary*>(this)->lock();
					}

					bool isLocked() const {
						return locked;
					}

					void unlock() {
						lock_guard<mutex> lock(manager->mt);
						if(locked) {
							locked = false;
							current = manager->unlockContext(current);
						}
					}

					void unlock() const {
						const_cast<temporary*>(this)->unlock();
					}
			};

			static SharedContext_ex &getInstance() {
				static SharedContext_ex sc;
				return sc;
			}

			list<thread::id> getThreadsUsed() {
				return mapKeys(free_contexts);
			}

			list<context*> getFreeContexts() {
				return mapValues(free_contexts);
			}

			list<context*> getLockedContexts() {
				return mapKeys(locked_contexts);
			}

			temporary getMyThreadTemporary() {
				lock_guard<mutex> lock(mt);
				return temporary(this, getMyThreadContext());
			}

		private:

			// every action in the shared context is locked
			mutex mt;
			// each thread has one context for free requests
			map<thread::id, context*> free_contexts;
			// every locked context has a thread he was previously belonging to
			map<context*, thread::id> locked_contexts;

			int contexts_conter=0;

			SharedContext_ex() = default;
			SharedContext_ex(const SharedContext_ex&) = delete;
			SharedContext_ex &operator=(const SharedContext_ex&) = delete;

			/**
			 * find value in a map
			 * @param value a value to find
			 * @param from the starting position of where to look for
			 * @param to the ending position - excluding from search
			 * @return an iterator to the first key value pair in the map containing the value,
			 * 			or the iterator 'to' given if non found.
			 */
			template<typename V, typename Iterator>
			static Iterator findMapValueInRange(const V &value, Iterator from, Iterator to) {
				for(auto i=from;i != to; i++) {
					if(i->second == value) {
						return i;
					}
				}
				return to;
			}

			/**
			 * find value in a map from the beginning to the end
			 * @param mp the map to find the value in
			 * @param value a value to find
			 * @return an iterator to the first key value pair in the map containing the value,
			 * 			or an iterator to end() if non found.
			 */
			template<typename K, typename V>
			inline typename map<K,V>::iterator findMapValue(map<K,V> &mp, const V &value) {
				return findMapValueInRange(value, mp.begin(), mp.end());
			}

			/**
			 * get a list with all the map keys
			 * @param mp a map from which we will obtain the keys
			 * @return a list with all the map keys
			 */
			template<typename K, typename V>
			static list<K> mapKeys(map<K,V> &mp) {
				list<K> ret;
				for(auto i=mp.begin();i != mp.end(); i++) {
					ret.push_back(i->first);
				}
				return ret;
			}

			/**
			 * get a list with all the map values
			 * values that present more then once will be in the list more then once
			 * @param mp a map from which we will obtain the values
			 * @return a list with all the map values
			 */
			template<typename K, typename V>
			static list<V> mapValues(map<K,V> &mp) {
				list<V> ret;
				for(auto i=mp.begin();i != mp.end(); i++) {
					ret.push_back(i->second);
				}
				return ret;
			}

			void useContext(context *ctx) {
				ctx->number_holders++;
			}

			context *getThreadContext(thread::id tid) {
				auto it = free_contexts.find(tid), end = free_contexts.end();
				if(it != end) {
					return it->second;
				}
				return (free_contexts[tid] = new context(contexts_conter++));
			}
			context *getMyThreadContext() {
				return getThreadContext(this_thread::get_id());
			}
			context *getMyFreeContext() {
				return getMyThreadContext();
			}
			context *getFreeContext(context *in_use) {
				context *now = getMyFreeContext();
				if(in_use == nullptr) {
					useContext(now);
				} else if(now != in_use) {
					// migrate to another thread context
					deleteFreeContext(in_use);
					useContext(now);
				}
				return now;
			}
			void deleteFreeContext(thread::id tid) {
				auto it = free_contexts.find(tid);
				if(--((it->second)->number_holders) == 0) {
					delete it->second;
					free_contexts.erase(it);
				}
			}
			void deleteFreeContext(context *ctx) {
				if(ctx != nullptr) {
					if(--(ctx->number_holders) == 0) {
						auto it = findMapValue(free_contexts, ctx), end = free_contexts.end();
						if(it != end) {
							delete ctx;
							free_contexts.erase(it);
						}
					}
				}
			}

			void lockContext(context *ctx) {
				// remove the context from free context list and add it to locked list
				auto it = findMapValue(free_contexts, ctx), end = free_contexts.end();
				if(it != end) {
					locked_contexts[ctx] = it->first;
					free_contexts.erase(it);
				}
			}
			context *unlockContext(context *ctx) {
				if(ctx != nullptr) {
					auto ctx_locked = locked_contexts.find(ctx), ctx_locked_end = locked_contexts.end();
					if(ctx_locked != ctx_locked_end) {
						// merge two free contexts for the thread
						// if thread already have a free context delete my instance
						auto fthread = free_contexts.find(ctx_locked->second), fthread_end = free_contexts.end();
						if (fthread != fthread_end) {
							fthread->second->number_holders += ctx->number_holders;
							delete ctx;
							ctx = fthread->second;
						} else {
							free_contexts[ctx_locked->second] = ctx;
						}
						locked_contexts.erase(ctx_locked);
						return ctx;
					}
				}
				return nullptr;
			}
			context *getMyLockedContext() {
				// find an unlocked context to lock
				context *i = getMyFreeContext();
				lockContext(i);
				return i;
			}
			context *getLockedContext(context *in_use) {
				context *now = getMyLockedContext();
				if(in_use == nullptr) {
					useContext(now);
				} else if(now != in_use) {
					// migrate to another thread context
					deleteFreeContext(in_use);
					useContext(now);
				}
				return now;
			}

	};

	typedef SharedContext_ex<BN_CTX, BN_CTX_new, BN_CTX_free, nullptr> BN_SHARED_CONTEXT_MANAGER;
	typedef BN_SHARED_CONTEXT_MANAGER::temporary BN_SHARED_CONTEXT;
	typedef SharedContext_ex<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free, EVP_MD_CTX_copy> EVP_MD_SHARED_CONTEXT_MANAGER;
	typedef EVP_MD_SHARED_CONTEXT_MANAGER::temporary EVP_MD_SHARED_CONTEXT;

}
#endif

