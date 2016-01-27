// PasswordDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertDecoderTest.h"
#include "PasswordDlg.h"
#include "afxdialogex.h"


// CPasswordDlg dialog

IMPLEMENT_DYNAMIC(CPasswordDlg, CDialog)

CPasswordDlg::CPasswordDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPasswordDlg::IDD, pParent)
{

}

CPasswordDlg::~CPasswordDlg()
{
}

void CPasswordDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CPasswordDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CPasswordDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CPasswordDlg message handlers


void CPasswordDlg::OnBnClickedOk()
{
	GetDlgItemText(IDC_EDIT_PASSWORDDLG_PSW, m_strPassword);

	CDialog::OnOK();
}


BOOL CPasswordDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	GetDlgItem(IDC_EDIT_PASSWORDDLG_PSW)->SetFocus();

	return FALSE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
