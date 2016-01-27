
// CertDecoderTestDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertDecoderTest.h"
#include "CertDecoderTestDlg.h"
#include "afxdialogex.h"
#include "PasswordDlg.h"
#include <map>

using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CCertDecoderTestDlg dialog
CCertDecoderTestDlg::CCertDecoderTestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCertDecoderTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hDecoderDll = NULL;
	m_pfLoadCertFile = NULL;
	m_pfSaveCertFile = NULL;
	m_pfReleaseCert = NULL;
	m_pICertificate = NULL;
}

void CCertDecoderTestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CCertDecoderTestDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DESTROY()
	ON_BN_CLICKED(IDC_BTN_OPEN, &CCertDecoderTestDlg::OnClickedBtnOpen)
	ON_BN_CLICKED(IDC_BTN_EXPORT, &CCertDecoderTestDlg::OnClickedBtnExport)
	ON_BN_CLICKED(IDC_RADIO_TYPE_CSP, &CCertDecoderTestDlg::OnBnClickedRadioTypeCsp)
	ON_BN_CLICKED(IDC_RADIO_TYPE_OPENSSL, &CCertDecoderTestDlg::OnBnClickedRadioTypeOpenssl)
END_MESSAGE_MAP()


// CCertDecoderTestDlg message handlers

BOOL CCertDecoderTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CListCtrl *pCertListCtrl = (CListCtrl*)GetDlgItem(IDC_LIST_CERTINFO);
	pCertListCtrl->SetExtendedStyle(pCertListCtrl->GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	pCertListCtrl->InsertColumn(0, _T("项"), LVCFMT_LEFT, 120);
	pCertListCtrl->InsertColumn(1, _T("值"), LVCFMT_LEFT, 400);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCertDecoderTestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CCertDecoderTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CCertDecoderTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCertDecoderTestDlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	m_pfReleaseCert(m_pICertificate);
	m_pICertificate = NULL;
	if (m_hDecoderDll)
	{
		::FreeLibrary(m_hDecoderDll);
		m_hDecoderDll = NULL;
	}
}

void CCertDecoderTestDlg::OnBnClickedRadioTypeCsp()
{
	ULONG ulError = 0;

	if (!LoadDecoderDll(_T("CSPCertDecoder.dll")))
	{
		CString strErr;
		ulError = GetLastError();
		strErr.Format(_T("加载DLL文件 CSPCertDecoder.dll 失败, 错误码：0x%x"), ulError);
		MessageBox(strErr, _T("失败"), MB_OK);
	}
}


void CCertDecoderTestDlg::OnBnClickedRadioTypeOpenssl()
{
	ULONG ulError = 0;

	if (!LoadDecoderDll(_T("OpenSSLCertDecoder.dll")))
	{
		CString strErr;
		ulError = GetLastError();
		strErr.Format(_T("加载DLL文件 OpenSSLCertDecoder.dll 失败, 错误码：0x%x"), ulError);
		MessageBox(strErr, _T("失败"), MB_OK);
	}
}


void CCertDecoderTestDlg::OnClickedBtnOpen()
{
	ULONG ulRes;
	LPSTR lpszFile = NULL;
	LPSTR lpszPassword = NULL;
	CString strCertFile;
	CString strPfxPassword;

	if (!m_pfLoadCertFile)
	{
		MessageBox(_T("证书解析DLL文件未加载！"));
		return;
	}

	USES_CONVERSION;

	CFileDialog dlgOpen(TRUE, _T(""), _T(""), OFN_CREATEPROMPT | OFN_PATHMUSTEXIST, 
		_T("X509证书文件(*.cer)|*.cer|P7证书文件(*.p7b)|*.p7b|P12证书文件(*.pfx)|*.pfx|所有文件(*.*)|*.*||"));
	if (dlgOpen.DoModal() == IDOK)
	{
		strCertFile = dlgOpen.GetPathName();
		SetDlgItemText(IDC_EDIT_CERTFILE, strCertFile);
	}
	else
	{		
		return;
	}	

	CListCtrl* pCertInfoList = (CListCtrl*)GetDlgItem(IDC_LIST_CERTINFO);
	pCertInfoList->DeleteAllItems();

	if (m_pICertificate && m_pfReleaseCert) 
	{
		m_pfReleaseCert(m_pICertificate);
		m_pICertificate = NULL;
	}

	strCertFile.MakeLower();
	if (strCertFile.Find(_T(".pfx")) != -1)
	{
		CPasswordDlg dlg;
		if (dlg.DoModal() == IDOK)
		{
			strPfxPassword = dlg.m_strPassword;
		}
		else
		{
			return;
		}
	}

#ifdef UNICODE
	lpszFile = W2A(strCertFile.GetBuffer(strCertFile.GetLength()));
	lpszPassword = W2A(strPfxPassword.GetBuffer(strPfxPassword.GetLength()));
#else
	lpszFile = strCertFile.GetBuffer(strCertFile.GetLength());
	lpszPassword = strPfxPassword.GetBuffer(strPfxPassword.GetLength());
#endif	//UNICODE

	ulRes = m_pfLoadCertFile(lpszFile, lpszPassword, &m_pICertificate);
	if (CERT_ERR_OK != ulRes)
	{
		CString strErr;
		strErr.Format(_T("解析证书失败, 错误码：0x%x"), ulRes);
		MessageBox(strErr, _T("失败"), MB_OK);
		return;
	}

	// Parser Certificate and show info
	ParserCertificate(m_pICertificate);
}


void CCertDecoderTestDlg::OnClickedBtnExport()
{	
	ULONG ulRes;
	ULONG ulCertDataLen = 0;
	LPBYTE lpCertData = NULL;
	LPSTR lpszFile = NULL;
	CString strCertFile;

	if (!m_pICertificate || !m_pfSaveCertFile)
	{
		MessageBox(_T("当前无证书！"));
		return;
	}

	USES_CONVERSION;

	CFileDialog dlgSave(FALSE, _T(".cer"), _T(""), OFN_CREATEPROMPT | OFN_PATHMUSTEXIST, 
		_T("X509证书文件(*.cer)|*.cer|所有文件(*.*)|*.*||"));
	if (dlgSave.DoModal() == IDOK)
	{
		strCertFile = dlgSave.GetPathName();
	}
	else
	{		
		return;
	}
	
#ifdef UNICODE
	lpszFile = W2A(strCertFile.GetBuffer(strCertFile.GetLength()));
#else
	lpszFile = strCertFile.GetBuffer(strCertFile.GetLength());
#endif	//UNICODE

	ulRes = m_pfSaveCertFile(lpszFile, m_pICertificate);
	if (CERT_ERR_OK != ulRes)
	{
		CString strErr;
		strErr.Format(_T("解析证书失败, 错误码：0x%x"), ulRes);
		MessageBox(strErr, _T("失败"), MB_OK);
		return;
	}
	else
	{
		MessageBox(_T("证书导出成功！"));
	}
}


BOOL CCertDecoderTestDlg::LoadDecoderDll(LPTSTR lpscDLLFile)
{
	if (m_hDecoderDll)
	{
		m_pfReleaseCert(m_pICertificate);
		m_pICertificate = NULL;
		::FreeLibrary(m_hDecoderDll);
		m_hDecoderDll = NULL;
	}
	m_hDecoderDll = LoadLibrary(lpscDLLFile);
	if (!m_hDecoderDll)
	{
		return FALSE;
	}

	m_pfLoadCertFile = (LoadCertFileProc)GetProcAddress(m_hDecoderDll, "LoadCertFile");
	m_pfSaveCertFile = (SaveCertFileProc)GetProcAddress(m_hDecoderDll, "SaveCertFile");
	m_pfReleaseCert = (ReleaseCertProc)GetProcAddress(m_hDecoderDll, "ReleaseCert");
	if (!m_pfLoadCertFile || !m_pfSaveCertFile || !m_pfReleaseCert)
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CCertDecoderTestDlg::ParserCertificate(ICertificate *pCert)
{
	ULONG ulRes = 0;
	ULONG ulIndex = 0;
	ULONG ulValLen = 0;
	ULONG ulVersion = 0;
	ULONG ulKeyUsage = 0;
	ULONG ulKeyAlg = 0;
	ULONG ulExtCount = 0;
	ULONG ulHashAlg = 0;
	ULONG ulHashLen = 0;	
	CHAR csSignatureAlg[64] = {0};
	CHAR csSN[64] = {0};
	CHAR csCN[64] = {0};
	CHAR csDN[64] = {0};
	LPBYTE lpbtHash = NULL;
	SYSTEMTIME stStart = {0}, stEnd = {0};
	CListCtrl* pCertInfoListCtrl = (CListCtrl*)GetDlgItem(IDC_LIST_CERTINFO);

	USES_CONVERSION;

	if (!pCert)
	{
		return FALSE;
	}

	pCertInfoListCtrl->DeleteAllItems();

	// Version
	CString strVersion;
	ulRes = pCert->get_Version(&ulVersion);
	strVersion.Format(_T("V%d"), ulVersion);
	pCertInfoListCtrl->InsertItem(ulIndex, _T("版本"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, strVersion);

	// SN
	ulValLen = 64;
	ulRes = pCert->get_SN(csSN, &ulValLen);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("序列号"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, A2W(csSN));

	// 签名算法
	ulValLen = 64;
	CString strSigantureAlg;
	ulRes = pCert->get_SignatureAlgOid(csSignatureAlg, &ulValLen);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("签名算法"), 0);
	if (_stricmp(csSignatureAlg, CERT_SIGNATURE_ALG_SHA1RSA) == 0)
	{
		strSigantureAlg.Format(_T("sha1RSA (%s)"), A2W(csSignatureAlg));
	}
	else if (_stricmp(csSignatureAlg, CERT_SIGNATURE_ALG_SM3SM2) == 0)
	{
		strSigantureAlg.Format(_T("sha1SM2 (%s)"), A2W(csSignatureAlg));
	}
	else
	{
		strSigantureAlg.Format(_T("%s"), A2W(csSignatureAlg));
	}
	pCertInfoListCtrl->SetItemText(ulIndex, 1, strSigantureAlg);
	
	// 颁发者
	ulValLen = 64;
	ulRes = pCert->get_Issuer(csCN, &ulValLen);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("颁发者"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, A2W(csCN));
	
	// DN
	ulValLen = 64;
	ulRes = pCert->get_SubjectName(csDN, &ulValLen);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("拥有者"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, A2W(csDN));

	// Valid date
	CString strStartDate, strEndDate;
	ulRes = pCert->get_ValidDate(&stStart, &stEnd);
	strStartDate.Format(_T("%04d-%02d-%02d"), stStart.wYear, stStart.wMonth, stStart.wDay);
	strEndDate.Format(_T("%04d-%02d-%02d"), stEnd.wYear, stEnd.wMonth, stEnd.wDay);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("生效日期"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, strStartDate);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("失效日期"), 0);
	pCertInfoListCtrl->SetItemText(ulIndex, 1, strEndDate);

	// Key usage
	ulRes = pCert->get_KeyUsage(&ulKeyUsage);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("密钥用法"), 0);
	if (CERT_USAGE_SIGN == ulKeyUsage)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("签名"));
	}
	else if (CERT_USAGE_EXCH == ulKeyUsage)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("加密"));
	}
	else
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("未知"));
	}

	// Key alg
	ulRes = pCert->get_KeyType(&ulKeyAlg);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("密钥算法标识"), 0);
	if (CERT_KEY_ALG_RSA == ulKeyAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("RSA"));
	}
	else if (CERT_KEY_ALG_ECC == ulKeyAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("ECC"));
	}
	else if (CERT_KEY_ALG_DSA == ulKeyAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("DSA"));
	}
	else if (CERT_KEY_ALG_DH == ulKeyAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("DH"));
	}
	else
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("未知"));
	}
	
	pCertInfoListCtrl->InsertItem(++ulIndex, _T(""), 0);

	// Extension property
	map<LPCSTR, LPCSTR> mapExtensionName;
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_AUTHORITY_IDENTIFIER,		"颁发机构密钥标识符"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_AUTHORITY_KEY_IDENTIFIER2,	"颁发机构密钥标识符"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_BASIC_CONSTRAINTS,			"基本约束"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_BASIC_CONSTRAINTS2,		"基本约束"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_KEY_USAGE,					"密钥用法"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_ENHANCED_KEY_USAGE,		"增强型密钥用法"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_SUBJECT_DENTIFIER,			"使用者密钥标识"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_CRL_DIST_POINTS,			"CRL 分发点"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_AUTHORITY_INFO_ACCESS,		"颁发机构信息访问"));
	mapExtensionName.insert(map<LPCSTR, LPCSTR>::value_type(CERT_EXT_NETSCAPE_CERT_TYPE,		"Netscape Cert Type"));
	pCert->get_ExtensionCnt(&ulExtCount);
	for (ULONG i = 0; i < ulExtCount; i++)
	{
		BOOL bIsCrit = FALSE;
		ULONG ulOidLen = 64;
		ULONG ulValueLen = 512;
		CHAR csOid[64] = {0};
		CHAR csValue[512] = {0};

		ulRes = pCert->get_ExtensionOid(i, csOid, &ulOidLen, &bIsCrit);
		if (CERT_ERR_OK != ulRes)
		{
			continue;
		}

		ulRes = pCert->get_ExtensionByOid(csOid, csValue, &ulValueLen);
		if (CERT_ERR_OK == ulRes && ulValueLen > 0)
		{
			LPCSTR lpDisplayName = NULL;
			for (map<LPCSTR, LPCSTR>::const_iterator it = mapExtensionName.begin();
				 it != mapExtensionName.end();
				 it++)
			{
				if (_stricmp(csOid, it->first) == 0)
				{
					lpDisplayName = it->second;
					break;
				}
			}
			if (!lpDisplayName)
			{
				lpDisplayName = csOid;
			}
#ifdef UNICODE
			pCertInfoListCtrl->InsertItem(++ulIndex, A2W(lpDisplayName), 0);
			pCertInfoListCtrl->SetItemText(ulIndex, 1, A2W(csValue));
#else
			pCertInfoListCtrl->InsertItem(++ulIndex, lpDisplayName, 0);
			pCertInfoListCtrl->SetItemText(ulIndex, 1, csValue);
#endif	//UNICODE
		}
	}
	
	pCertInfoListCtrl->InsertItem(++ulIndex, _T(""), 0);

	// Hash alg
	ulRes = pCert->get_HashAlgID(&ulHashAlg);
	pCertInfoListCtrl->InsertItem(++ulIndex, _T("HASH(指纹)算法标识"), 0);
	if (CERT_HASH_ALG_MD5 == ulHashAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("MD5"));
	}
	else if (CERT_HASH_ALG_SHA1 == ulHashAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("SHA1"));
	}
	else if (CERT_HASH_ALG_SHA256 == ulHashAlg)
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("SHA256"));
	}
	else
	{
		pCertInfoListCtrl->SetItemText(ulIndex, 1, _T("未知"));
	}

	// Hash value
	ulRes = pCert->get_HashValue(NULL, &ulHashLen);
	if (CERT_ERR_OK == ulRes && ulHashLen > 0)
	{
		CString strHash, strTmp;
		lpbtHash = new BYTE[ulHashLen];
		pCert->get_HashValue(lpbtHash, &ulHashLen);
		pCertInfoListCtrl->InsertItem(++ulIndex, _T("HASH(指纹)"), 0);
		for (ULONG i = 0; i < ulHashLen; i++)
		{
			strTmp.Format(_T("%x "), lpbtHash[i]);
			strHash += strTmp;
		}
		pCertInfoListCtrl->SetItemText(ulIndex, 1, strHash);
		delete []lpbtHash;
		lpbtHash = NULL;
	}
	
	// Public Key
	CString strPubKey;
	CertPubKey pubKey = {0};
	pCert->get_PublicKey(&pubKey);
	if (pubKey.ulAlg == CERT_KEY_ALG_RSA)
	{
		CString strTmp;
		strTmp.Format(_T("%02X %02X %02X %02X "), pubKey.rsa.ulBits&0x000000FF, (pubKey.rsa.ulBits>>8)&0x000000FF
											   , (pubKey.rsa.ulBits>>16)&0x000000FF, (pubKey.rsa.ulBits>>24)&0x000000FF);
		strPubKey += strTmp;
		for (ULONG i = 0; i < pubKey.rsa.ulBits/8; i++)
		{
			if (pubKey.rsa.ulWrapType == RSA_PUBKEY_WRAPPED_GM)
			{
				strTmp.Format(_T("%02X "), pubKey.rsa.btModulus[(256-pubKey.rsa.ulBits/8)+i]);
			}
			else
			{
				strTmp.Format(_T("%02X "), pubKey.rsa.btModulus[i]);
			}
			strPubKey += strTmp;
		}
		strTmp.Format(_T("%02X %02X %02X %02X "), pubKey.rsa.btExp[0], pubKey.rsa.btExp[1], pubKey.rsa.btExp[2], pubKey.rsa.btExp[3]);
		strPubKey += strTmp;
	}
	else
	{
		CString strTmp;
		strTmp.Format(_T("%02X %02X %02X %02X "), pubKey.ecc.ulBits&0x000000FF, (pubKey.ecc.ulBits>>8)&0x000000FF
											   , (pubKey.ecc.ulBits>>16)&0x000000FF, (pubKey.ecc.ulBits>>24)&0x000000FF);
		strPubKey += strTmp;
		for (int i = 0; i < 64; i++)
		{
			strTmp.Format(_T("%02X "), pubKey.ecc.ulX[i]);
			strPubKey += strTmp;
		}
		for (int i = 0; i < 64; i++)
		{
			strTmp.Format(_T("%02X "), pubKey.ecc.ulY[i]);
			strPubKey += strTmp;
		}
	}
	SetDlgItemText(IDC_EDIT_PUBKEY, strPubKey);

	return TRUE;
}

