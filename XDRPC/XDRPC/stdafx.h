// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include <xtl.h>
#include <xboxmath.h>
#include <iostream>


#define SetCodeData(Dest, Source, Size) { memcpy(Dest, Source, Size); }

#ifndef _DEBUG
//disable debug printing in release
//#define printf
#endif

#include "kernel.h"