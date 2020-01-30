// CrestronDLLSigningTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <windows.h>
#include <processthreadsapi.h>
#include <errhandlingapi.h>
#include <string.h>
#include <strsafe.h>

#define DEBUG 0
#define VERBOSE 1

#define DEFAULT_SPLUSCC_PATH "C:\\Program Files (x86)\\Crestron\\Simpl\\SPlusCC.exe"
#define DEFAULT_SERIES 3

#define DUMMY_USP_CONTENTS "function main() {}\n"

using std::cout;
using std::endl;
using std::string;

//parameters to be passed into threads
struct SignDLLParam
{
	string target_path;
	string spluscc_path;
	int series = 0;
};

//thread-safe system message handler
void VerboseMsg(LPCSTR msg)
{
	if (!VERBOSE)
		return;
	
	size_t buf_sz = strlen(msg) + 32;
	LPSTR buf = (LPSTR)LocalAlloc(LMEM_ZEROINIT, buf_sz);

	if (buf == NULL)
		return;

	//create string
	StringCchPrintfA(buf, buf_sz, "[THREAD %d]  %s\n", GetCurrentThreadId(), msg);

	//output string all at once
	cout << buf;

	LocalFree(buf);
}

//thread-safe error message handler with path
void ErrorHandler(LPCSTR msg, LPCSTR path)
{
	LPSTR err_str;
	DWORD err = GetLastError();

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)& err_str,
		0, NULL);

	size_t buf_sz = strlen(msg) + strlen(path) + strlen(err_str) + 64;
	LPSTR buf = (LPSTR)LocalAlloc(LMEM_ZEROINIT, buf_sz);

	if (buf == NULL)
		return;

	//if path isn't defined, do not include it as part of the error message
	if (path != NULL)
	{
		StringCchPrintfA(buf, buf_sz, "[THREAD %d]\n\t%s\n\tRelevant path: %s\n\tError code %ld: %s\n", GetCurrentThreadId(), msg, path, err, err_str);
	}
	else
	{
		StringCchPrintfA(buf, buf_sz, "[THREAD %d]\n\t%s\n\tError code %ld: %s\n", GetCurrentThreadId(), msg, err, err_str);
	}

	//output data all at once
	cout << buf;

	LocalFree(buf);
	
	if (err_str != NULL)
		LocalFree(err_str);
}

DWORD InjectTargetDLL(string existing_path, string payload_path)
{
	//delete the freshly compiled dummy file
	if (!DeleteFileA(existing_path.c_str()))
	{
		ErrorHandler("ERROR: Could not delete dummy DLL file.", existing_path.c_str());
		return(EXIT_FAILURE);
	}
	//replace the previous file with our own DLL that we want to sign
	if (!CopyFileA(payload_path.c_str(), existing_path.c_str(), false))
	{
		ErrorHandler("ERROR: Could not copy target.", payload_path.c_str());
		return(EXIT_FAILURE);
	}

	return(EXIT_SUCCESS);
}

//replaces uppercase letters with lowercase
char* CharArrayToLowerCase(char* arr)
{
	for (unsigned int i = 0; i < strlen(arr); i++)
	{
		if (arr[i] >= 'A' && arr[i] <= 'Z')
		{
			arr[i] += 0x20;
		}
	}
	return arr;
}

//instructions
void Usage()
{
	cout << "\nCrestronDLLSigningTool [options] <\"target_path\"> [options]\n\n";
	cout << "options:\n";
	cout << "\t/?        \t\tPrint this message\n";
	cout << "\t/SSPLUSCC=\t\tPath to the Simpl+ Cross-compiler if installed in non-default directory\n";
	cout << "\t/SERIES=  \t\t2 or 3. Specifies if this is a Crestron 2-series or 3-series DLL file\n" << endl;

	exit(EXIT_SUCCESS);
}

int _SignDLL(LPVOID lpParam, string &tempdir_path)
{
		SignDLLParam* param = (SignDLLParam*)lpParam;
	string target_path = param->target_path;
	string spluscc_path = param->spluscc_path;
	int series = param->series;

	//get full path so that the file operations work no matter where the application is called from
	LPSTR target_full_path = new char[BUFSIZ];
	if (!GetLongPathNameA(target_path.c_str(), target_full_path, BUFSIZ))
	{
		ErrorHandler("ERROR: Could not get target's full path.", target_path.c_str());
		return(EXIT_FAILURE);
	}

	//extract the filename of the target DLL and name the dummy USP file with the same name
	char* target_fname = new char[BUFSIZ];
	char* target_ext = new char[BUFSIZ];
	if (_splitpath_s(target_full_path, NULL, 0, NULL, 0, target_fname, BUFSIZ, target_ext, BUFSIZ) == EINVAL)
	{
		ErrorHandler("Target path is invalid", target_full_path);
		return(EXIT_FAILURE);
	}
	if (strcmp(target_ext, ".dll"))
	{
		ErrorHandler("Target file is not a DLL file.", target_full_path);
		return(EXIT_FAILURE);
	}


	VerboseMsg("Obtaining temp directory...");

	//get a temp windows dir
	char* tempdir_path_c_arr = new char[BUFSIZ];
	if (!GetTempPathA(BUFSIZ, tempdir_path_c_arr))
	{
		ErrorHandler("ERROR: Failed to obtain temporary path.", NULL);
		return(EXIT_FAILURE);
	}

	//get a GUID and use it to create another directory within our temp directory
	//This is done because the GetTempPathA often returns the same path, and we need a unique directory for every thread instance
	GUID id;
	if (CoCreateGuid(&id) != S_OK)
	{
		ErrorHandler("ERROR: Failed to create GUID for temporary directory name.", NULL);
		return(EXIT_FAILURE);
	}

	tempdir_path = tempdir_path_c_arr;
	delete[] tempdir_path_c_arr;

	//converting GUID to string and appending to temp path
	size_t val_buf_sz = sizeof(long) * 2 + 1;
	char* val_c_arr = new char[val_buf_sz];

	_ltoa_s(id.Data1, val_c_arr, val_buf_sz, 16);
	tempdir_path.append(val_c_arr);
	_itoa_s(id.Data2, val_c_arr, val_buf_sz, 16);
	tempdir_path.append(val_c_arr);
	_itoa_s(id.Data3, val_c_arr, val_buf_sz, 16);
	tempdir_path.append(val_c_arr);
	for (int i = 0; i < 8; i++)
	{
		_itoa_s(id.Data4[i], val_c_arr, val_buf_sz, 16);
		tempdir_path.append(val_c_arr);
	}
	tempdir_path += '\\';
	delete[] val_c_arr;

	//finally, create the thread's temp directory within the windows temp dir
	if (!CreateDirectoryA(tempdir_path.c_str(), NULL))
	{
		switch (GetLastError())
		{
		case ERROR_ALREADY_EXISTS:
			VerboseMsg("Warning: Temp directory already exists.");
			break;
		default:
			ErrorHandler("ERROR: Could not create temp directory", tempdir_path.c_str());
			return(EXIT_FAILURE);
		}
	}

	//create a dummy USP file for compile using the filename extracted before from target DLL
	string dummy_usp_path = tempdir_path;
	dummy_usp_path.append(target_fname);
	dummy_usp_path.append(".usp");

	string dummy_dll_path;
	dummy_dll_path = tempdir_path;
	dummy_dll_path.append("SPlsWork\\");
	dummy_dll_path.append(target_fname);
	dummy_dll_path.append(target_ext);

	delete[] target_fname;
	delete[] target_ext;


	VerboseMsg("Creating dummy .usp file with target filename...");

	HANDLE dummy_usp_handle = CreateFileA(
		dummy_usp_path.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (dummy_usp_handle == INVALID_HANDLE_VALUE)
	{
		ErrorHandler("ERROR: Could not create dummy file", dummy_usp_path.c_str());
		return(EXIT_FAILURE);
	}

	//fill dummy file with the bare minimum amount of code so that it will actually compile
	string dummy_usp_contents = { DUMMY_USP_CONTENTS };
	if (!WriteFile(dummy_usp_handle, dummy_usp_contents.c_str(), dummy_usp_contents.length(), NULL, NULL))
	{
		ErrorHandler("ERROR: Could not write to dummy file.", dummy_usp_path.c_str());
		return(EXIT_FAILURE);
	}
	CloseHandle(dummy_usp_handle);

	//Once the dummy file is created and the handle is closed
	//Create the command string that will be used to invoke the Simpl+ Cross-Compiler
	//This uses the path to the CC and then appends the arguments to that string
	string spluscc_cmd = spluscc_path;
	spluscc_cmd.append(" \\target series");

	if (series == 2)
		spluscc_cmd.append("2");
	else if (series == 3)
		spluscc_cmd.append("3");
	spluscc_cmd.append(" \\rebuild \"");
	spluscc_cmd.append(dummy_usp_path.c_str());
	spluscc_cmd.append("\"");


	LPSTR spluscc_cmd_c_str = new char[spluscc_cmd.length() + 1];
	strcpy_s(spluscc_cmd_c_str, spluscc_cmd.length() + 1, spluscc_cmd.c_str());

	LPSTARTUPINFOA StartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION ProcessInformation = new PROCESS_INFORMATION();

	LPDEBUG_EVENT DebugEvent = new DEBUG_EVENT();
	DWORD DebugContinue;
	bool ProcessAlive;
	bool BreakpointReached = FALSE;

	VerboseMsg("Closed dummy file handle. Starting compile...");

	//Start Cross-Compiler process in debug mode
	if (!CreateProcessA(
		NULL,
		spluscc_cmd_c_str,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		StartupInfo,
		ProcessInformation
	))
	{
		ErrorHandler("ERROR: Failed to start Simpl+ Cross-Compiler process.", spluscc_path.c_str());
		return(EXIT_FAILURE);
	}
	delete[] spluscc_cmd_c_str;

	ProcessAlive = TRUE;
	LPSTR mod_path = new char[BUFSIZ];
	DWORD mod_path_size = BUFSIZ;
	string dll_str;

	//loop through debug events without affecting the process
	//once we detect that the process is loading cryptography-related DLLs
	//we assume that the compile is complete and that the process is ready to sign the compiled DLL from the dummy USP file
	//therefore before continuing the process, we swap the freshly compiled DLL with our target DLL for signing
	while (ProcessAlive)
	{
		WaitForDebugEvent(DebugEvent, INFINITE);
		DebugContinue = DBG_CONTINUE;

		switch (DebugEvent->dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			CloseHandle(DebugEvent->u.CreateProcessInfo.hFile);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			GetFinalPathNameByHandleA(DebugEvent->u.LoadDll.hFile, mod_path, mod_path_size, FILE_NAME_NORMALIZED);
			CloseHandle(DebugEvent->u.LoadDll.hFile);
			if (DEBUG) cout << "MODLOAD: " << mod_path << endl;

			if (BreakpointReached == FALSE)
			{
				dll_str = CharArrayToLowerCase(mod_path);
				if (dll_str.find("capicom") != string::npos)
				{
					VerboseMsg("Swapping dummy compiled DLL with target DLL for signing...");

					if (InjectTargetDLL(dummy_dll_path, target_full_path) == EXIT_FAILURE)
						return(EXIT_FAILURE);

					BreakpointReached = TRUE;
				}
			}
			break;
		case EXCEPTION_DEBUG_EVENT:
			DebugContinue = DBG_EXCEPTION_NOT_HANDLED;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			ProcessAlive = FALSE;
			VerboseMsg("Signing complete. Copying file back to target directory...");
			break;
		}

		ContinueDebugEvent(DebugEvent->dwProcessId, DebugEvent->dwThreadId, DebugContinue);
	}

	//stop debugging since process has terminated
	DebugActiveProcessStop(ProcessInformation->dwProcessId);

	//attempt to backup the target DLL in case the signing process has failed
	string target_full_path_bak = target_full_path;
	target_full_path_bak.append(".bak");

	if (!MoveFileA(target_full_path, target_full_path_bak.c_str()))
	{
		ErrorHandler("Warning: Failed to rename the original target file for backup.\n\tFile will be replaced by signed version.", target_full_path_bak.c_str());
	}

	//copy the signed DLL from the temp dir to replace the original target DLL
	if (!CopyFileA(dummy_dll_path.c_str(), target_path.c_str(), false))
	{
		ErrorHandler("ERROR: Failed to move signed DLL from temp directory.\n\tSigned DLL file can be found below",dummy_dll_path.c_str());
		exit(EXIT_FAILURE);
	}

	delete[] mod_path;
	delete DebugEvent;
	delete StartupInfo;
	delete ProcessInformation;

	return(EXIT_SUCCESS);
}

DWORD WINAPI SignDLL(LPVOID lpParam)
{
	string tempdir_path;
	int ret;

	ret = _SignDLL(lpParam, tempdir_path);

	VerboseMsg("Cleaning up temporary directory...");


	//creating a double null terminated string for SHFileOperations()
	int err, tempdir_path_fileop_sz = tempdir_path.length() + 2;
	char* tempdir_path_fileop = new char[tempdir_path_fileop_sz];
	strcpy_s(tempdir_path_fileop, tempdir_path_fileop_sz, tempdir_path.c_str());
	tempdir_path_fileop[tempdir_path_fileop_sz - 1] = '\0';

	//delete the temp directoy
	SHFILEOPSTRUCTA fileop =
	{
		NULL,
		FO_DELETE,
		tempdir_path_fileop,
		NULL,
		FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMATION,
		FALSE,
		NULL,
		NULL
	};

	if (err = SHFileOperationA(&fileop))
		ErrorHandler("Warning: Some elements in temp directory could not be deleted", tempdir_path.c_str());

	delete[] tempdir_path_fileop;

	return(ret);
}


int main(int argc, char* argv[])
{
	string spluscc_arg = {"/SPLUSCC="};
	string series_arg =  {"/SERIES=" };
	string help_arg = { "/?" };

	string spluscc_path;
	int series = 0;
	std::vector<string> targets;

	//parse the command line arguments
	string temp;
	for (int i = 1; i < argc; i++)
	{
		temp = argv[i];

		if (!temp.compare(help_arg))
		{
			Usage();
		}
		else if (!temp.compare(0, spluscc_arg.length(), spluscc_arg))
		{
			if (spluscc_path.length() == 0)
				spluscc_path = temp.substr(spluscc_arg.length(), temp.length() - spluscc_arg.length());
			else
				Usage();
		}
		else if (!temp.compare(0, series_arg.length(), series_arg))
		{
			if (series == 0)
			{
				series = atoi((temp.substr(series_arg.length(), temp.length() - series_arg.length())).c_str());

				if (series != 2 && series != 3)
					Usage();
			}
			else
				Usage();
		}
		else
			targets.push_back(temp);
	}

	//we require at least one target path, for others assume defaults if not specified
	if (targets.empty())
		Usage();
	if (spluscc_path.length() == 0)
		spluscc_path = DEFAULT_SPLUSCC_PATH;
	if (series == 0)
		series = DEFAULT_SERIES;


	size_t num_threads = targets.size();
	HANDLE *thread_handles = new HANDLE[num_threads];
	DWORD *thread_ids = new DWORD[num_threads];
	SignDLLParam *thread_params = new SignDLLParam[num_threads];

	//create worker threads for each file to sign
	for (size_t i = 0; i < num_threads; i++)
	{
		thread_params[i].target_path = targets[i];
		thread_params[i].spluscc_path = spluscc_path;
		thread_params[i].series = series;
		thread_handles[i] = CreateThread(NULL, 0, SignDLL, &(thread_params[i]), 0, &(thread_ids[i]));
	}

	//wait for all threads to be done
	WaitForMultipleObjects(num_threads, thread_handles, true, INFINITE);

	//cleanup
	for (size_t i = 0; i < num_threads; i++)
	{
		if (thread_handles[i] != NULL)
			CloseHandle(thread_handles[i]);
	}
	delete[] thread_params;

	return(EXIT_SUCCESS);
}
