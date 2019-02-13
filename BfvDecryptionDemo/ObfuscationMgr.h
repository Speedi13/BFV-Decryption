#pragma once
#include "FrostbiteSDK.h"

typedef DWORD64 QWORD;
typedef QWORD _QWORD;

typedef BYTE _BYTE;
typedef DWORD _DWORD;
typedef WORD _WORD;

template<typename T1, typename T2>
struct pair
{
	T1 first;
	T2 second;
};
template<typename T>
struct hash_node
{
	pair<_QWORD,T*> mValue;
	hash_node<T>* mpNext;
};
 
template<typename T>
struct hashtable
{
	_QWORD vtable;
	hash_node<T>** mpBucketArray;
	unsigned int mnBucketCount;
	unsigned int mnElementCount;
	//...
};
 
template<typename T>
struct hashtable_iterator
{
	hash_node<T>* mpNode;
	hash_node<T>** mpBucket;
};
 
hashtable_iterator<_QWORD> *__fastcall hashtable_find(hashtable<_QWORD>* table, hashtable_iterator<_QWORD>* iterator, _QWORD key);


fb::ClientPlayer* GetPlayerById( int id );
fb::ClientPlayer* GetLocalPlayer( void );
