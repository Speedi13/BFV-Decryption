#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include "FrostbiteSDK.h"
#include "ObfuscationMgr.h"

BYTE* FindPattern(BYTE* dwAddress, DWORD dwSize, BYTE* pbSig, char* szMask);

DWORD OFFSET_PredictedController = NULL;
DWORD WINAPI DllThread(PVOID pThreadParameter)
{
	UNREFERENCED_PARAMETER( pThreadParameter );

	AllocConsole();
	freopen("CONIN$", "r", stdin); 
	freopen("CONOUT$", "w", stdout); 
	freopen("CONOUT$", "w", stderr); 

	printf("DllThread started!\n");


	OFFSET_ObfuscationMgr = GetObfuscationMgr();
	printf("OFFSET_ObfuscationMgr: 0x%I64X\n",OFFSET_ObfuscationMgr);

	//Works for bf1 & bfv
	//0F ?? ?? ?? ?? ?? 48 83 ?? ?? ?? 00 00 00 0F 84 ?? ?? ?? ?? 48 83 ?? ?? ?? 00 00 00 75 ?? ?? ?? ?? E9

	//.xcode:000000014214DA0D 48 83 BE 30 02 00 00 00                 cmp     qword ptr [rsi+230h], 0
	//.xcode:000000014214DA15 0F 85 27 01 00 00                       jnz     loc_14214DB42			
	//.xcode:000000014214DA1B 48 83 BE C0 07 00 00 00                 cmp     qword ptr [rsi+7C0h], 0		
	//.xcode:000000014214DA23 0F 84 12 01 00 00                       jz      loc_14214DB3B			
	//.xcode:000000014214DA29 48 83 BE C8 07 00 00 00                 cmp     qword ptr [rsi+7C8h], 0		
	//.xcode:000000014214DA31 75 08                                   jnz     short loc_14214DA3B		
	//.xcode:000000014214DA33 4C 8B F7                                mov     r14, rdi			
	//.xcode:000000014214DA36 E9 83 00 00 00                          jmp     loc_14214DABE

	//x?????xx???xxxxx????xx???xxxx????x

	BYTE* StartAddress = (BYTE*)0x140001000;
	BYTE* HitAddress = NULL;
	while (true)
	{
		HitAddress = FindPattern( StartAddress, ~0, (BYTE*)"\x0F\x00\x00\x00\x00\x00\x48\x83\x00\x00\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00\x48\x83\x00\x00\x00\x00\x00\x00\x75\x00\x00\x00\x00\xE9", "x?????xx???xxxxx????xx???xxxx????x");
		//83 BF
		if ( HitAddress[-7] == 0x83 && HitAddress[-6] == 0xBF )
			break;
		//48 83 BE
		if ( HitAddress[-8] == 0x48 && HitAddress[-7] == 0x83 && HitAddress[-6] == 0xBE )
			break;
		StartAddress = HitAddress+5;
	}

	OFFSET_PredictedController = *(DWORD*)&HitAddress[9]; //currently 0x7C0
	printf("OFFSET_PredictedController = 0x%X\n",OFFSET_PredictedController);

	while (true)
	{
		//if you want to use this code in your external cheat look at the function below
		//BypassObfuscationMgr();
		
		Sleep( 1000 );
	
		__int32 maxPlayerCount = 70;

		fb::ClientPlayer* pLocalPlayer = GetLocalPlayer();
		if (!ValidPointer(pLocalPlayer)) continue;

		printf("pLocalPlayer = 0x%I64X\n",pLocalPlayer);
		printf("pLocalPlayer->m_pName = \"%s\"\n",pLocalPlayer->m_pName);

		for (int i = 0; i < maxPlayerCount; i++)
		{
			fb::ClientPlayer* pPlayer = GetPlayerById( i );
			if (!ValidPointer(pPlayer)) continue;
			printf("-------------------- Player --------------------\n");
			printf("[%i] pPlayer = 0x%I64X\n",i,pPlayer);
			printf("[%i] pPlayer->m_pName = \"%s\"\n",i,pPlayer->m_pName);
			fb::ClientSoldierEntity* pSoldierEntity = pPlayer->GetSoldier();
			if (!ValidPointer(pSoldierEntity)) continue;

			printf("[%i] pPlayer->GetSoldier() = 0x%I64X\n",i,pSoldierEntity);

			fb::LinearTransform transform;
			pSoldierEntity->GetTransform( &transform );

			printf("[%i] GetTransform = { %f, %f, %f }\n",i,transform.trans.x,transform.trans.y,transform.trans.z);

			fb::ClientSoldierPrediction* pPredictedController = pSoldierEntity->GetPredictedController().GetPtr( /*key: pSoldierEntity*/ );
			if (!ValidPointer(pPredictedController)) continue;
			printf("[%i] pSoldierEntity->ClientSoldierPrediction = 0x%I64X\n",i,pPredictedController);
			printf("[%i] pPredictedController->m_Position = { %f, %f, %f }\n",i,pPredictedController->m_Position.x,pPredictedController->m_Position.y,pPredictedController->m_Position.z);
		}
		printf("-------------------- END --------------------\n");
		puts("\n");
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DllThread, lpReserved, 0, NULL);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//-------------------------------------------------------------------------------
//https://github.com/learn-more/findpattern-bench/blob/master/patterns/kokole.h
bool DataCompare(BYTE* pData, BYTE* bSig, char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bSig)
	{
		if (*szMask == 'x' && *pData != *bSig)
			return false;
	}
	return (*szMask) == NULL;
}
BYTE* FindPattern(BYTE* dwAddress, DWORD dwSize, BYTE* pbSig, char* szMask)
{
	size_t length = strlen(szMask);
	for (DWORD i = NULL; i < dwSize - length; i++)
	{
		if (DataCompare(dwAddress + i, pbSig, szMask))
			return dwAddress + i;
	}
	return 0;
}
//-------------------------------------------------------------------------------
