/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

/*!
 *
 * Purpose:
 *
 * Redirects DnsQuery_A over a DNS/HTTP(s)
 * provider.
 *
!*/
D_SEC(D)  VOID WINAPI Sleep_HOOK(IN DWORD 	dwMilliseconds);
D_SEC(D) LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo);
