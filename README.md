# Project Simply_Stinger 
  - UAC Bypass & SYSTEM Privilege Escalation via COM Task Scheduler

> **Minimal and educational reimplementation of the "Stinger" exploit from the Vault 7 (CIA) leaks**, fully written in C with no external dependencies.  
> This program escalates privileges from an Administrator user to SYSTEM on Windows, by leveraging a self-elevated process and abusing COM and Task Scheduler interfaces.

---

## 🗂️ File

**`simply_stinger.c`**  
A single C file that:

- Exploits UAC via token duplication
- Lowers token integrity level
- Uses COM to create a SYSTEM-scheduled task
- Executes an arbitrary command as SYSTEM

---

## 📜 Background: Vault 7 and the "Stinger" Tool

In 2017, WikiLeaks published the **Vault 7** documents, exposing CIA hacking tools.  
One of these tools was **Stinger**, designed to bypass UAC and execute code as SYSTEM via Windows internals.

Stinger works by:

- Launching a self-elevated Microsoft-signed binary
- Duplicating the elevated token
- Downgrading token integrity
- Using COM (`TaskScheduler`) to spawn a SYSTEM task running attacker-controlled code

---

## 🧠 How It Works (Step by Step)

### 1. 📥 Launching a Self-Elevated Process

The user provides a self-elevated executable (e.g., signed Microsoft binary):

```
C:\Windows\System32\ComputerDefaults.exe
```

It’s launched using `ShellExecuteExW()` with the `runas` verb to trigger UAC.

👉 **Goal**: obtain the elevated administrator token from this process.

---

### 2. 🔓 Token Duplication

- `OpenProcessToken()` retrieves the process access token.
- `DuplicateTokenEx()` creates a **primary token**.
- A permissive ACL is assigned using `ConvertStringSecurityDescriptorToSecurityDescriptor()`.

---

### 3. 🔻 Lowering Token Integrity Level

COM rejects actions from high integrity tokens in certain contexts. To fix this:

- Internal function `NtSetInformationToken()` from `ntdll.dll` is used.
- The `TokenIntegrityLevel` is modified to `Medium`.
- A medium-level SID is created with `AllocateAndInitializeSid()`.

👉 **This allows COM to accept and operate with the impersonated token**.

---

### 4. 🌀 COM Impersonated Thread

A new thread is launched:

- `ImpersonateLoggedOnUser()` sets the elevated identity.
- `CoInitializeEx()` initializes COM.
- `ITaskService::Connect()` connects to the Task Scheduler service.

---

### 5. 📆 Creating a SYSTEM Task via COM

The thread dynamically creates a scheduled task:

- `NewTask()` defines the task
- `RegistrationInfo` sets author
- `Principal` is configured with:
  - ID = "Principal1"
  - `LogonType` = `TASK_LOGON_SERVICE_ACCOUNT`
  - `RunLevel` = `TASK_RUNLEVEL_HIGHEST`
- `Trigger`: creates a `ITimeTrigger` to start in 1 minute
- `Action`: creates an `IExecAction` to execute the desired binary with arguments

---

### 6. 🚀 Task Registration and Execution

- A random 8-character name is generated for the task.
- `RegisterTaskDefinition()` registers the task with:
  - User: `SYSTEM`
  - Auth: `TASK_LOGON_SERVICE_ACCOUNT`
- Task is immediately executed via `IRunningTask::Run()`.

---

### 7. 🧼 Cleanup

- All COM objects are released via `Release()`
- Impersonation ends with `RevertToSelf()`
- Handles are closed with `CloseHandle()`
- `CoUninitialize()` finalizes COM

---

## 🛠️ Compilation

Using MinGW:

```bash
gcc simply_stinger.c -o stinger.exe -ladvapi32 -lshell32 -luser32 -lole32 -ltaskschd -luuid -loleaut32
```

---

## ▶️ Usage Example

```bash
stinger.exe "C:\Windows\System32\ComputerDefaults.exe" "C:\Windows\System32\cmd.exe" /c whoami > C:\temp\result.txt
```

- First arg = UAC-triggering executable
- Second arg = binary to run as SYSTEM
- Following args = arguments to pass to the binary

---

## 🧪 Recommended AutoElevate Binaries

Any executable that triggers UAC will work:

- `ComputerDefaults.exe`
- `fodhelper.exe`
- `eventvwr.exe`
- `sdclt.exe` (older versions)
- or any signed binary with `requireAdministrator` manifest

---

## ✅ Requirements

- User must be in **Administrators group**
- UAC must be enabled (but not at "Always deny")
- Local COM access must be allowed (default)
- Tested on **Windows 7 to 10**
- Partial compatibility on Windows 11

---

## ⚠️ Legal Warning

**This project is for educational and ethical research purposes only.**  
Unauthorized usage may be illegal depending on your jurisdiction.  
**You are solely responsible** for what you do with this code.

---

## 📚 References

- [WikiLeaks Vault 7](https://wikileaks.org/ciav7p1/)
- [Hacker House - Stinger (original)](https://github.com/hackerhouse-opensource/Stinger)
- [Microsoft COM Task Scheduler API](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [Token Integrity Levels - Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [UAC Bypass Techniques - enigma0x3](https://enigma0x3.net/)
