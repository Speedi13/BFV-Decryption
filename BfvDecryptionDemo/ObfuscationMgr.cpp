#include "ObfuscationMgr.h"
void* OFFSET_ObfuscationMgr = 0;

//In case you don't want to Include the whole directx library
#if !defined(D3DX11_SDK_VERSION)
typedef struct D3D11_MAPPED_SUBRESOURCE
{
	void *pData;
	UINT RowPitch;
	UINT DepthPitch;
} 	D3D11_MAPPED_SUBRESOURCE;
typedef 
enum D3D11_MAP
{
	D3D11_MAP_READ	= 1,
	D3D11_MAP_WRITE	= 2,
	D3D11_MAP_READ_WRITE	= 3,
	D3D11_MAP_WRITE_DISCARD	= 4,
	D3D11_MAP_WRITE_NO_OVERWRITE	= 5
} D3D11_MAP;
struct ID3D11DeviceContext
{
	virtual void Function0(); //
	virtual void Function1(); //
	virtual void Function2(); //
	virtual void Function3(); //
	virtual void Function4(); //
	virtual void Function5(); //
	virtual void Function6(); //
	virtual void Function7(); //
	virtual void Function8(); //
	virtual void Function9(); //
	virtual void Function10(); //
	virtual void Function11(); //
	virtual void Function12(); //
	virtual void Function13(); //
	virtual HRESULT STDMETHODCALLTYPE Map( void *pResource, UINT Subresource, D3D11_MAP MapType, UINT MapFlags, D3D11_MAPPED_SUBRESOURCE *pMappedResource);
	virtual void STDMETHODCALLTYPE Unmap(  void *pResource, UINT Subresource);
};
struct ID3D11Buffer
{
};
#endif

struct ObfuscationMgr
{
	char _0x0000[224];
	__int64 m_E0; //0x00E0 
	char _0x00E8[16];
	__int64 m_DecryptionFunction; //0x00F8
	__int64 m_EncryptedBuffer; //0x0100  		//encrypted ID3D11Buffer*
	__int64 m_EncryptedDeviceContext; //0x0108 	//encrypted ID3D11DeviceContext*
	__int64 m_EncryptedDevice; //0x0110 		//encrypted ID3D11Device*
	__int64 m_D3d11; //0x0118 					//encrypted d3d11.dll
};

__int64 __fastcall PointerXorMultiplayer(__int64 ValueToXor /*RCX*/, __int64 EncryptedBuffer /*RDX*/, __int64 EncryptedDeviceContext /*R8*/ )
{
	__int64 XorD3D11 = 0x2CE4356EA77515AEui64;

	ID3D11DeviceContext* pDeviceContext = (ID3D11DeviceContext*)( EncryptedDeviceContext ^ XorD3D11 );
	ID3D11Buffer* pBuffer = (ID3D11Buffer*)( EncryptedBuffer ^ XorD3D11 );

	D3D11_MAPPED_SUBRESOURCE MappedSubResource = {0};

	HRESULT hResult = pDeviceContext->Map( pBuffer, NULL, D3D11_MAP_READ, NULL, &MappedSubResource );
	if ( !SUCCEEDED(hResult) || !MappedSubResource.pData )
		return ValueToXor;

	__int64 XorKey = *(__int64 *)MappedSubResource.pData;

	pDeviceContext->Unmap( pBuffer, NULL );

	return ValueToXor ^ XorKey;
}

__int64 __fastcall PointerXorSinglePlayer(__int64 RCX )
{
	return RCX ^ 0x598447EFD7A36912ui64;
}

_QWORD __fastcall PointerXor(_QWORD RCX, _QWORD RDX)
{
//original function code from sub_1415780F0
//RAX = ( *(_QWORD *)(RCX + 0xD8) ^ *(_QWORD *)(RCX + 0xF8) )
//RCX = RDX
//RDX = *(_QWORD *)(RCX + 0x100)
//R8  = *(_QWORD *)(RCX + 0x108)
//jmp RAX

	_QWORD pObfuscationMgr = RCX - 8;

	_QWORD EncryptedBuffer = *(_QWORD *)(pObfuscationMgr + 0x108 - 8);
	_QWORD EncryptedDeviceContext = *(_QWORD *)(pObfuscationMgr + 0x110 - 8);

	DWORD64 DecryptFunction = ( *(_QWORD *)(pObfuscationMgr + 0xE0) ^ *(_QWORD *)(pObfuscationMgr + 0x100 - 8) );
	
	//Index: 0 = singleplayer | 1 = MP
	static DWORD64 DecryptionFunctions[2] = {0,0};

	if ( DecryptionFunctions[0] != DecryptFunction &&
		 DecryptionFunctions[1] != DecryptFunction )
	{
		DWORD64 FncCodeAddress = (DWORD64)DecryptFunction;
		if (*(BYTE*)FncCodeAddress == 0xE9)
			FncCodeAddress = (DWORD64)ResolveRelativePtr( (void*)( FncCodeAddress + 1 ) );
		if ( *(WORD*)FncCodeAddress == 0x44C6 ) //Singleplayer
		{
			DecryptionFunctions[0] = DecryptFunction;
		}
		else
			DecryptionFunctions[1] = DecryptFunction;
	}

	bool IsMultiPlayerEncryption = DecryptionFunctions[1] == DecryptFunction;
	if ( IsMultiPlayerEncryption != true || EncryptedBuffer == NULL || EncryptedDeviceContext == NULL )
		return (_QWORD)PointerXorSinglePlayer( RDX );
	
	return (_QWORD)PointerXorMultiplayer( RDX, EncryptedBuffer, EncryptedDeviceContext );
}
 
fb::ClientPlayer* EncryptedPlayerMgr__GetPlayer( QWORD EncryptedPlayerMgr, int id )
{
	_QWORD XorValue1 = *(_QWORD *)(EncryptedPlayerMgr + 0x20) ^ *(_QWORD *)(EncryptedPlayerMgr + 8);
	_QWORD XorValue2 = PointerXor(    *(_QWORD *)(EncryptedPlayerMgr + 0x28),
									  *(_QWORD *)(EncryptedPlayerMgr + 0x10) );
	if (!ValidPointer(XorValue2)) return nullptr;
	_QWORD Player = XorValue1 ^ *(_QWORD *)( XorValue2 + 8 * id);
	return (fb::ClientPlayer*)Player;
}
fb::ClientPlayer* GetPlayerById( int id )
{
	fb::ClientGameContext* pClientGameContext = fb::ClientGameContext::GetInstance();
	if (!ValidPointer(pClientGameContext)) return nullptr;
	fb::ClientPlayerManager* pPlayerManager = pClientGameContext->m_clientPlayerManager;
	if (!ValidPointer(pPlayerManager)) return nullptr;
 
	_QWORD pObfuscationMgr = (_QWORD)OFFSET_ObfuscationMgr;
 
	_QWORD PlayerListXorValue = *(_QWORD*)( (_QWORD)pPlayerManager + 0xF8 );
	_QWORD PlayerListKey = PlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 );
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)(pObfuscationMgr + 8 + 8);
	hashtable_iterator<_QWORD> iterator = {0};
 
	hashtable_find(table, &iterator, PlayerListKey);
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] )
		return nullptr;
	if (!ValidPointer(iterator.mpNode)) return nullptr;
	_QWORD EncryptedPlayerMgr = (_QWORD)iterator.mpNode->mValue.second;
	if (!ValidPointer(EncryptedPlayerMgr)) return nullptr;
 
	_DWORD MaxPlayerCount = *(_DWORD *)(EncryptedPlayerMgr + 0x18);
	if( MaxPlayerCount != 70u || MaxPlayerCount <= (unsigned int)(id) ) return nullptr;

	return EncryptedPlayerMgr__GetPlayer( EncryptedPlayerMgr, id );
}
 
fb::ClientPlayer* GetLocalPlayer( void )
{
	fb::ClientGameContext* pClientGameContext = fb::ClientGameContext::GetInstance();
	if (!ValidPointer(pClientGameContext)) return nullptr;
	fb::ClientPlayerManager* pPlayerManager = pClientGameContext->m_clientPlayerManager;
	if (!ValidPointer(pPlayerManager)) return nullptr;
 
	_QWORD pObfuscationMgr = (_QWORD)OFFSET_ObfuscationMgr;
 
	_QWORD LocalPlayerListXorValue = *(_QWORD*)( (_QWORD)pPlayerManager + 0xF0 );
	_QWORD LocalPlayerListKey = LocalPlayerListXorValue ^ *(_QWORD *)(pObfuscationMgr + 0xE0 );
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)(pObfuscationMgr + 8 + 8);
	hashtable_iterator<_QWORD> iterator = {0};
 
	hashtable_find(table, &iterator, LocalPlayerListKey);
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] )
		return nullptr;
	if (!ValidPointer(iterator.mpNode)) return nullptr;

	_QWORD EncryptedPlayerMgr = (_QWORD)iterator.mpNode->mValue.second;
	if (!ValidPointer(EncryptedPlayerMgr)) return nullptr;
 
	_DWORD MaxPlayerCount = *(_DWORD *)(EncryptedPlayerMgr + 0x18);
	if( MaxPlayerCount != 1u ) return nullptr;
	
	return EncryptedPlayerMgr__GetPlayer( EncryptedPlayerMgr, 0 );
}

hashtable_iterator<_QWORD> *__fastcall hashtable_find(hashtable<_QWORD>* table, hashtable_iterator<_QWORD>* iterator, _QWORD key)
{  
	unsigned int mnBucketCount = table->mnBucketCount;

	//bfv
	unsigned int startCount = (_QWORD)(key) % (_QWORD)(mnBucketCount);
 
	//bf1
	//unsigned int startCount = (unsigned int)(key) % mnBucketCount;

	hash_node<_QWORD>* node = table->mpBucketArray[ startCount ];
 
	if ( ValidPointer(node) && node->mValue.first ) 
	{
		while ( key != node->mValue.first )
		{
			node = node->mpNext;
			if ( !node || !ValidPointer(node) 
				)
				goto LABEL_4;
		}
		iterator->mpNode = node;
		iterator->mpBucket = &table->mpBucketArray[ startCount ];
	}
	else
	{
LABEL_4:
		iterator->mpNode = table->mpBucketArray[ mnBucketCount ];
		iterator->mpBucket = &table->mpBucketArray[ mnBucketCount ];
	}
	return iterator;
}


void* DecryptPointer( DWORD64 EncryptedPtr, DWORD64 PointerKey )
{
	_QWORD pObfuscationMgr = (_QWORD)OFFSET_ObfuscationMgr;
 
	if ( !(EncryptedPtr & 0x8000000000000000) )
		return nullptr; //invalid ptr
 
	_QWORD hashtableKey = *(_QWORD *)(pObfuscationMgr + 0xE0 ) ^ PointerKey;
 
	hashtable<_QWORD>* table = (hashtable<_QWORD>*)( pObfuscationMgr + 0x78 );
	hashtable_iterator<_QWORD> iterator = {};
 
	hashtable_find( table, &iterator, hashtableKey );
	if ( iterator.mpNode == table->mpBucketArray[table->mnBucketCount] ) 
		return nullptr;
	if (!ValidPointer(iterator.mpNode))
		return nullptr;
	_QWORD EncryptionKey = NULL;


	EncryptionKey = PointerXor( (_QWORD)pObfuscationMgr + 8, (_QWORD)(iterator.mpNode->mValue.second) );

	EncryptionKey ^= (5 * EncryptionKey);
 
	_QWORD DecryptedPtr = NULL;
	BYTE* pDecryptedPtrBytes = (BYTE*)&DecryptedPtr;
	BYTE* pEncryptedPtrBytes = (BYTE*)&EncryptedPtr;
	BYTE* pKeyBytes = (BYTE*)&EncryptionKey;
 
	for (char i = 0; i < 7; i++)
	{
		pDecryptedPtrBytes[i] = ( pKeyBytes[i] * 0x3B ) ^ ( pEncryptedPtrBytes[i] + pKeyBytes[i] );
		EncryptionKey += 8;
	}
	pDecryptedPtrBytes[7] = pEncryptedPtrBytes[7];
 
	DecryptedPtr &= ~( 0x8000000000000000 ); //to exclude the check bit
 
	return (void*)DecryptedPtr;
}


void* GetObfuscationMgr()
{
	////////////////////////////////////////////////////////////// Shellcodes //////////////////////////////////////////////////////////////
	BYTE getObfuscationMgrShellCode[] =	{
		0x48, 0x8B, 0x04, 0x24,												//mov rax,[rsp]
		0x8B, 0x40, 0xF0,													//mov eax,[rax-10]
		0x3D, 0x1D, 0x51, 0x8C, 0x4D,										//cmp eax,4D8C511D
		0x75, 0x07,															//jne [RIP+9]
		0x48, 0x89, 0x0d, 0x1B, 0x00, 0x00, 0x00,							//mov [RIP+1B],rcx
		0x65, 0x48, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	//mov rax,gs:[00000030]
		0x8B, 0x40, 0x48,													//mov eax,[rax+48]
		0xC3,																//ret

		//Buffer to store the obf mgr addr:
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	BYTE OirignalFunctionCode[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE JumpToShellcode[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	HANDLE hProcessHandle = GetCurrentProcess();

	//the kernel32 and nt-dll is mapped to the same virtual address for every process ;)
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	//lookup the address of the exported function "GetCurrentThreadId"
	void* GetCurrentThreadIdFunctionAddr = (void*)GetProcAddress( hKernel32, "GetCurrentThreadId" );

	//allocate memory for the shellcode which will retrieve the obfuscation mgr address 
	void* ShellCodeAddr = VirtualAllocEx( hProcessHandle, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	//write the shellcode into the allocated memory
	WriteProcessMemory( hProcessHandle, ShellCodeAddr, getObfuscationMgrShellCode, 52, nullptr );

	//write the address of the main shellcode into the jump shellcode
	*(void**)&JumpToShellcode[6] = ShellCodeAddr;

	//read the original code of the GetCurrentThreadId function to restore it later
	ReadProcessMemory( hProcessHandle, GetCurrentThreadIdFunctionAddr, OirignalFunctionCode, 14, nullptr );

	//write jump to shellcode into the GetCurrentThreadId function
	WriteProcessMemory( hProcessHandle, GetCurrentThreadIdFunctionAddr, JumpToShellcode, 14, nullptr );

	void* ObfuscationMgr = (void*)(nullptr);
	void* ShellCodeResultAddr = (void*)( (char*)ShellCodeAddr+0x30 );

	//wait for shellcode to retrieve the obfuscation mgr address 
	do
	{
		Sleep( 100 ); 
		ReadProcessMemory( hProcessHandle, ShellCodeResultAddr, &ObfuscationMgr, sizeof(void*), nullptr );
	} while ( !ObfuscationMgr );

	//restore the original function code
	WriteProcessMemory( hProcessHandle, GetCurrentThreadIdFunctionAddr, OirignalFunctionCode, 14, nullptr );

	Sleep( 500 );//wait to make sure its not executed anymore

	VirtualFreeEx( hProcessHandle, ShellCodeAddr, NULL, MEM_RELEASE );

	return ObfuscationMgr;
}


///////////////////////////////////////////////////// SHELLCODE /////////////////////////////////////////////////////
BYTE getMultiplayerXorKey__shellcode[] = {
 //ObfMgrAddr (+0x00)
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 //Result: (+0x08)
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 //function code start: (+0x10)
 0x4C, 0x8B, 0xDC,                                              //- mov r11,rsp
 0x49, 0x89, 0x5B, 0x08,                                        //- mov [r11+08],rbx
 0x49, 0x89, 0x73, 0x10,                                        //- mov [r11+10],rsi
 0x57,                                                          //- push rdi
 0x48, 0x83, 0xEC, 0x40,                                        //- sub rsp,40
 0x48, 0xB9, 0xAE, 0x15, 0x75, 0xA7, 0x6E, 0x35, 0xE4, 0x2C,    //- mov rcx,2CE4356EA77515AE
 0x48, 0x8B, 0x05, 0xCF, 0xFF, 0xFF, 0xFF,                      //- mov rax,[RIP-31]
 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00,                            //- mov r9d,00000001
 0x45, 0x33, 0xC0,                                              //- xor r8d,r8d
 0x48, 0x8B, 0xB8, 0x08, 0x01, 0x00, 0x00,                      //- mov rdi,[rax+00000108]
 0x48, 0x8B, 0xB0, 0x00, 0x01, 0x00, 0x00,                      //- mov rsi,[rax+00000100]
 0x48, 0x33, 0xF9,                                              //- xor rdi,rcx
 0x48, 0x33, 0xF1,                                              //- xor rsi,rcx
 0x49, 0x8D, 0x4B, 0xE8,                                        //- lea rcx,[r11-18]
 0x48, 0x8B, 0x07,                                              //- mov rax,[rdi]
 0x49, 0x89, 0x4B, 0xE0,                                        //- mov [r11-20],rcx
 0x83, 0x64, 0x24, 0x20, 0x00,                                  //- and dword ptr [rsp+20],00
 0x48, 0x8B, 0xD6,                                              //- mov rdx,rsi
 0x48, 0x8B, 0xCF,                                              //- mov rcx,rdi
 0xFF, 0x50, 0x70,                                              //- call qword ptr [rax+70]
 0x85, 0xC0,                                                    //- test eax,eax
 0x78, 0x2B,                                                    //- js [RIP+0x2d]
 0x48, 0x8B, 0x5C, 0x24, 0x30,                                  //- mov rbx,[rsp+30]
 0x48, 0x85, 0xDB,                                              //- test rbx,rbx
 0x74, 0x21,                                                    //- je [RIP+0x23]
 0x4C, 0x8B, 0x0F,                                              //- mov r9,[rdi]
 0x48, 0x8B, 0x1B,                                              //- mov rbx,[rbx]
 0x45, 0x33, 0xC0,                                              //- xor r8d,r8d
 0x48, 0x8B, 0xD6,                                              //- mov rdx,rsi
 0x48, 0x8B, 0xCF,                                              //- mov rcx,rdi
 0x41, 0xFF, 0x51, 0x78,                                        //- call qword ptr [r9+78]
 0x48, 0x8B, 0xC3,                                              //- mov rax,rbx
 0x48, 0x89, 0x05, 0x76, 0xFF, 0xFF, 0xFF,                      //- mov [RIP-8A],rax
 0x33, 0xC0,                                                    //- xor eax,eax
 0xEB, 0x05,                                                    //- jmp [RIP+0x7]
 0xB8, 0xE9, 0x03, 0x00, 0x00,                                  //- mov eax,000003E9
 0x48, 0x8B, 0x5C, 0x24, 0x50,                                  //- mov rbx,[rsp+50]
 0x48, 0x8B, 0x74, 0x24, 0x58,                                  //- mov rsi,[rsp+58]
 0x48, 0x83, 0xC4, 0x40,                                        //- add rsp,40
 0x5F,                                                          //- pop rdi
 0xC3,                                                          //- ret 
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//the following code is retrieving the multiplayer xor key that gets stored on the graphics card in a way that should be easy to implement into an external cheat.
__int64 getMultiplayerXorKey( void* ObfMgr )
{
	HANDLE hProcessHandle = GetCurrentProcess();

	//check if any of the following values is zero
	/*
	__int64 m_EncryptedBuffer; //0x0100  		//encrypted ID3D11Buffer*
	__int64 m_EncryptedDeviceContext; //0x0108 	//encrypted ID3D11DeviceContext*
	__int64 m_EncryptedDevice; //0x0110 		//encrypted ID3D11Device*
	__int64 m_D3d11; //0x0118 			//encrypted d3d11.dll
	*/
	for (int i = 0; i < 4; i++)
	{
		__int64 value = *(__int64 *)( (char*)ObfMgr + 0x100 + (i * 8) );
		if (value == 0) return 0;
	}

	//allocate memory for the shellcode which will retrieve the multiplayer xor key
	void* ShellCodeAddr = VirtualAllocEx( hProcessHandle, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	//write the shellcode into the allocated memory
	WriteProcessMemory( hProcessHandle, ShellCodeAddr, getMultiplayerXorKey__shellcode, 171, nullptr );

	//write the address of the obfuscation mgr into the shellcode:
	WriteProcessMemory( hProcessHandle, ShellCodeAddr, &ObfMgr, 8, nullptr );

	void* ShellCodeResultAddr = (void*)( (char*)ShellCodeAddr+0x8 );
	void* ShellCodeStartAddr = (void*)( (char*)ShellCodeAddr+0x10 );

	//start the shellcode:
	HANDLE hThreadHandle = CreateRemoteThread( hProcessHandle, nullptr, NULL, (LPTHREAD_START_ROUTINE)ShellCodeStartAddr, nullptr, NULL, nullptr );

	//wait for the code to finish
	while ( WaitForSingleObject(hThreadHandle, 0) == WAIT_TIMEOUT  )
		Sleep( 100 );

	//retrieve the result:
	__int64 MultiplayerXorKey = 0;
	ReadProcessMemory( hProcessHandle, ShellCodeResultAddr, &MultiplayerXorKey, 8, nullptr );

	//free the shellcode:
	VirtualFreeEx( hProcessHandle, ShellCodeAddr, NULL, MEM_RELEASE );

	return MultiplayerXorKey;
}
