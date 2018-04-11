// base64_file.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "base64_file.h"
#include <string>
#include <memory>
#include <Wincrypt.h>
#pragma comment(lib,"crypt32")
#include "cJSON.h"
#include "base64.h"
using namespace gloox;

#define  ERROR   "0100000004"
#define  SUCCESS  "0000000000"
#define  INVALID_FILE "0000000001"
#define  LEN_1024  1024
#define  ASSERT_PTR(jason,ret) \
	strcpy((ret),ERROR);\
	if((jason) == nullptr)\
{\
	return (ret);\
}\

#define DELETE_ARRAY(ptr) \
	if(nullptr != ptr)\
{\
	delete[] ptr;\
	ptr = nullptr;\
}\

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 唯一的应用程序对象

CWinApp theApp;

using namespace std;

static unsigned long get_file_size(const char *path)
{
	unsigned long filesize = -1;
	FILE *fp;
	fp = fopen(path, "r");
	if(fp == NULL)
		return filesize;
	fseek(fp, 0L, SEEK_END);
	filesize = ftell(fp);
	fclose(fp);
	return filesize;
}

const char* readfile64(const char* jason)
{
	char* ret = new char[LEN_1024];
	ASSERT_PTR(jason,ret);
	cJSON * root = cJSON_Parse(jason);
	char filename[LEN_1024] = {};
	if (!root) return ret;
	cJSON * item = cJSON_GetObjectItem(root, "filename");
	sprintf(filename,"%s",item->valuestring);
	unsigned long fileSize = get_file_size(filename);
	if (fileSize <= 0) return ret;

	FILE* fp = fopen(filename, "rb");
	char* inBuffer = new char[fileSize];
	ULONG uReaded = fread(inBuffer, 1, fileSize, fp);

	const BYTE* pbBinary = (const BYTE*)inBuffer;
	DWORD dwLen;
	CryptBinaryToStringA(pbBinary, fileSize, CRYPT_STRING_BASE64, NULL, &dwLen);

	char* pCrypt1 = new char[dwLen];
	CryptBinaryToStringA(pbBinary, fileSize, CRYPT_STRING_BASE64, pCrypt1, &dwLen);
	fclose(fp);

	std::string strIn(pCrypt1);
	int nIn = strIn.length();

	if (inBuffer)
	{
		delete[] inBuffer;
		inBuffer = NULL;
	}
	if (pCrypt1)
	{
		delete[] pCrypt1;
		pCrypt1 = NULL;
	}
	std::string strOut = Base64::encode64(strIn);
	int nOut = strOut.length();
	DELETE_ARRAY(ret);
	char* base64 = new char[nOut + 1];
	sprintf(base64,"%s",strOut.c_str());
	return base64;
}

const char* _64tofile(const char* jason)
{
	char* ret = new char[LEN_1024];
	ASSERT_PTR(jason,ret);
	cJSON * root = cJSON_Parse(jason);
	if (!root) return ret;

	char filename[LEN_1024] = {};
	cJSON * item = cJSON_GetObjectItem(root, "filename");
	sprintf(filename,"%s",item->valuestring);

	//char* base64 = new char[strlen(jason) + 1];
	item = cJSON_GetObjectItem(root, "base64");
	string strOut(item->valuestring);

	std::string strFile = Base64::decode64(strOut);
	int nFile = strFile.length();
	int nFileSize = strFile.size();

	DWORD cbBinary;
	DWORD dwSkip;
	DWORD dwFlags;
	CryptStringToBinaryA(strFile.data(), nFile+1, CRYPT_STRING_BASE64, NULL, &cbBinary, &dwSkip, &dwFlags);

	BYTE* outBuffer = new BYTE[cbBinary];
	CryptStringToBinaryA(strFile.data(), nFile+1, CRYPT_STRING_BASE64, outBuffer, &cbBinary, &dwSkip, &dwFlags);

	FILE* fp2 = fopen(filename, "wb");
	if (!fp2) return ret;
	ULONG uWrite = fwrite(outBuffer, 1, cbBinary+1, fp2);
	fclose(fp2);
	if (outBuffer)
	{
		delete[] outBuffer;
		outBuffer = NULL;
	}
	strcpy(ret,SUCCESS);
	return ret;
}


int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(NULL);

	if (hModule != NULL)
	{
		// 初始化 MFC 并在失败时显示错误
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO: 更改错误代码以符合您的需要
			_tprintf(_T("错误: MFC 初始化失败\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO: 在此处为应用程序的行为编写代码。
			
			std::unique_ptr<const char*>p(new const char*(readfile64("{\"filename\":\"D:\\\\job\\\\greatwall\\\\test\\\\1.jpg\"}")));
			if (!*p.get())
				return -1;
			int len = strlen(*p.get());
			printf("%s\n",*p.get());
			
			char* pcOut = new char[len + MAX_PATH];
			memset(pcOut,0x00,sizeof(pcOut));
			sprintf(pcOut,"{\"base64\":\"%s\",\"filename\":\"%s\"}",*p.get(),"D:\\\\job\\\\greatwall\\\\test\\\\out.jpg");
			//const char* ret = _64tofile(pcOut);
			std::unique_ptr<const char*>ret(new const char*(_64tofile(pcOut)));
	
			printf("%s\n",*ret.get());


			if (pcOut)
			{
				delete[] pcOut;
				pcOut = NULL;
			}
			getchar();
		}
	}
	else
	{
		// TODO: 更改错误代码以符合您的需要
		_tprintf(_T("错误: GetModuleHandle 失败\n"));
		nRetCode = 1;
	}

	return nRetCode;
}
