/*
Copyright 2025 William Johnson <williamj.inbox@gmail.com>

Licensed under the Apache License, Version 2.0 (the 
"License"); you may not use this file except in compliance 
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, 
software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific 
language governing permissions and limitations under the License.
*/
#include "win.h"

const uint8_t has_process(const char *p_list[], const uint8_t p_count)
{
    DWORD processIds[1024], bytesNeeded, procCount;
    HANDLE hProcess = NULL;
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
    if ( !EnumProcesses(processIds, sizeof(processIds), &bytesNeeded) )
        return 0;
    procCount = bytesNeeded / sizeof(DWORD);
    for ( uint32_t p = 0; p < procCount; p++ ) {
        if( processIds[p] != 0 ) {
            hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                    FALSE,
                                    processIds[p] );
            if ( hProcess != NULL ) {
                HMODULE hMod;
                DWORD cbNeeded;
                if ( EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded) ) {
                    GetModuleBaseName(hProcess,
                                    hMod,
                                    szProcessName,
                                    sizeof(szProcessName)/sizeof(TCHAR));
                    CloseHandle(hProcess);
                    for ( uint8_t q = 0; q < p_count; q++ ) {
                        if ( strcmp(p_list[q], szProcessName) == 0 )
                            return 1;
    }}}}}
    return 0;
}
