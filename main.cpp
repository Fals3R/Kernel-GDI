#include "hook.hpp"
#include "utils.hpp"

#define PATCOPY             (DWORD)0x00F00021

void* (NTAPI* original_DxgkSubmitCommand)(void* unused);
void* ptr_DxgkSubmitCommand = 0;
static bool is_hooked = false;
static bool is_render_inited = false;

void driver_unload(PDRIVER_OBJECT driver_object) {
	UNREFERENCED_PARAMETER(driver_object);
	if (is_hooked) {
		destroy_hook(ptr_DxgkSubmitCommand, (void*)original_DxgkSubmitCommand);
	}
}

typedef HWND(NTAPI* tNtUserGetForegroundWindow)();
tNtUserGetForegroundWindow NtUserGetForegroundWindow = NULL;

typedef HDC(NTAPI* tNtUserGetDC)(HWND hwnd);
tNtUserGetDC NtUserGetDC = NULL;

typedef bool(NTAPI* tNtGdiPatBlt)(HDC hdc, int x, int y, int x2, int y2, DWORD rop);
tNtGdiPatBlt NtGdiPatBlt = NULL;

// сделано на скорую руку, очевидно что PoC
void* hook_DxgkSubmitCommand(void* unused) {
	if (!is_render_inited) {
		NtUserGetForegroundWindow = (tNtUserGetForegroundWindow)get_ssdt_function(4159 - 4096, true);
		NtUserGetDC = (tNtUserGetDC)get_ssdt_function(4109 - 4096, true);
		NtGdiPatBlt = (tNtGdiPatBlt)get_ssdt_function(4188 - 4096, true);
	}
	const auto hdc = NtUserGetDC(NtUserGetForegroundWindow());
	NtGdiPatBlt(hdc, 15, 15, 35, 35, PATCOPY);
	return original_DxgkSubmitCommand(unused);
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	driver_object->DriverUnload = driver_unload;

	// брал индекты тут - https://hfiref0x.github.io/w32ksyscalls.html
	// [index - 4096] = адрес функции (только для win32k)
	void** func = reinterpret_cast<void**>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "DxgkSubmitCommand"));
	if (!init_hook((void*)hook_DxgkSubmitCommand, func, (void**)&original_DxgkSubmitCommand)) {
		// не удалось хукнуть, что-то пошло не так...
		return STATUS_SUCCESS;
	}

	is_hooked = true;

	// запоминаем оригинал чтобы потом снять хук
	ptr_DxgkSubmitCommand = func;

	return STATUS_SUCCESS;
}