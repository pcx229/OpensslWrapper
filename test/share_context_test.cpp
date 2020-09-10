
#include <thread>
#include <mutex>
#include <chrono>
#include <iostream>
using namespace std;

#include <gtest/gtest.h>

#include <openssl/bn.h>

#include "shared_context.h"
using namespace crypto;

namespace {

TEST(SharedContext, UsageWithSingleCommand) {
	BN_SHARED_CONTEXT ctx;
	BIGNUM *a = BN_new();
	BN_dec2bn(&a, "15");
	BIGNUM *b = BN_new();
	BN_dec2bn(&b, "15");
	BIGNUM *r = BN_new();
	BN_mul(r,a,b,ctx);
	unsigned int n = BN_get_word(r);
	ASSERT_EQ(n, 225);
}

TEST(SharedContext, LockOnMainThread) {
	BN_SHARED_CONTEXT ctx;
	BN_SHARED_CONTEXT ctx2;
	ASSERT_TRUE(*ctx == *ctx2);
	ctx2.lock();
	ASSERT_FALSE(*ctx == *ctx2);
	ctx2.unlock();
	ASSERT_TRUE(*ctx == *ctx2);
}

void testMigrationThread2();
void testMigrationThread3();

void *mctx_ptr = nullptr;

int numberOfThreadsUsed() {
	return BN_SHARED_CONTEXT_MANAGER::getInstance().getThreadsUsed().size();
}

int getFirstThreadUsedId() {
	stringstream ss;
	int i;
	ss << BN_SHARED_CONTEXT_MANAGER::getInstance().getThreadsUsed().front();
	ss >> i;
	return i;
}

int getFirstFreeContextId() {
	BN_SHARED_CONTEXT_MANAGER::context* i = BN_SHARED_CONTEXT_MANAGER::getInstance().getFreeContexts().front();
	return i->my_id;
}
/*
void printInfo(int thread_id) {
	cerr << "thread " << thread_id << endl;
	cerr << "first ctx id " << getFirstFreeContextId() << endl;
	cerr << "current threads number " << numberOfThreadsUsed() << endl;
	cerr << "first thread used id " << getFirstThreadUsedId() << endl;
}
*/
TEST(SharedContext, ThreadsMigrations) {
	BN_SHARED_CONTEXT shared;
	ASSERT_EQ(numberOfThreadsUsed(), 1);
	ASSERT_EQ(getFirstThreadUsedId(), 1);
	mctx_ptr = &shared;
	int now_id = getFirstFreeContextId();
	thread t1(testMigrationThread2);
	thread t2(testMigrationThread3);
	t1.join();
	t2.join();
	ASSERT_NE(now_id, getFirstFreeContextId());
}

void testMigrationThread2() {
	BN_SHARED_CONTEXT *t = (BN_SHARED_CONTEXT*)mctx_ptr;
	BN_SHARED_CONTEXT &ctx = *t;
	ASSERT_EQ(getFirstThreadUsedId(), 1);
	int now_id;
	*ctx;
	ASSERT_EQ(getFirstThreadUsedId(), 2);
	ASSERT_EQ(numberOfThreadsUsed(), 1);
	now_id = getFirstFreeContextId();
	this_thread::sleep_for(chrono::milliseconds(4000));
	ASSERT_EQ(getFirstThreadUsedId(), 3);
	*ctx;
	ASSERT_NE(now_id, getFirstFreeContextId());
	ASSERT_EQ(numberOfThreadsUsed(), 1);
	ASSERT_EQ(getFirstThreadUsedId(), 2);
}

void testMigrationThread3() {
	BN_SHARED_CONTEXT *t = (BN_SHARED_CONTEXT*)mctx_ptr;
	BN_SHARED_CONTEXT &ctx = *t;
	this_thread::sleep_for(chrono::milliseconds(2000));
	int now_id;
	*ctx;
	ASSERT_EQ(numberOfThreadsUsed(), 1);
	ASSERT_EQ(getFirstThreadUsedId(), 3);
	now_id = getFirstFreeContextId();
	this_thread::sleep_for(chrono::milliseconds(1000));
	ASSERT_EQ(now_id, getFirstFreeContextId());
	*ctx;
	ASSERT_EQ(now_id, getFirstFreeContextId());
	this_thread::sleep_for(chrono::milliseconds(4000));
	ASSERT_NE(now_id, getFirstFreeContextId());
	ASSERT_EQ(getFirstThreadUsedId(), 2);
}

}
