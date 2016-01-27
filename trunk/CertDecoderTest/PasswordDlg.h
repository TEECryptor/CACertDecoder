#pragma once


// CPasswordDlg dialog

class CPasswordDlg : public CDialog
{
	DECLARE_DYNAMIC(CPasswordDlg)

public:
	CPasswordDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPasswordDlg();

// Dialog Data
	enum { IDD = IDD_DLG_PASSWROD };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()

public:
	CString		m_strPassword;
	afx_msg void OnBnClickedOk();
	virtual BOOL OnInitDialog();
};
