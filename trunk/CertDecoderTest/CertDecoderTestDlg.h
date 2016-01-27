
// CertDecoderTestDlg.h : header file
//

#pragma once

#include "../Include/ICertificate.h"


/*	DLL export function definition */
typedef ULONG (__cdecl *LoadCertFileProc)(LPSTR, LPSTR, ICertificate**);
typedef ULONG (__cdecl *SaveCertFileProc)(LPSTR, ICertificate*);
typedef ULONG (__cdecl *ReleaseCertProc)(ICertificate*);


// CCertDecoderTestDlg dialog
class CCertDecoderTestDlg : public CDialogEx
{
// Construction
public:
	CCertDecoderTestDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_CERTDECODERTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

private:
	ICertificate*	m_pICertificate;

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	HINSTANCE			m_hDecoderDll;
	LoadCertFileProc	m_pfLoadCertFile;
	SaveCertFileProc	m_pfSaveCertFile;
	ReleaseCertProc		m_pfReleaseCert;
private:
	BOOL	LoadDecoderDll(LPTSTR lpscDLLFile);
	BOOL	ParserCertificate(ICertificate *pCert);
public:
	afx_msg void OnDestroy();
	afx_msg void OnClickedBtnOpen();
	afx_msg void OnClickedBtnExport();
	afx_msg void OnBnClickedRadioTypeCsp();
	afx_msg void OnBnClickedRadioTypeOpenssl();
};
