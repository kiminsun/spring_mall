package com.my.spring.member.pass_lock;

import com.my.spring.member.nonmember.vo.NonMemberVO;
import com.my.spring.member.vo.MemberVO;

public class Login {
	
	
	private SHA256 sha;
	
	public MemberVO password_Lock(MemberVO vo) throws Exception {
		String pw1 = "";
		String pw2 = "";
		
		sha = SHA256.getInsatnce();
		//1�� ��ȣȭ
		pw1 = sha.getSha256(vo.getMember_pwd().getBytes());
		//2�� ��ȣȭ
		pw2 = BCrypt.hashpw(pw1, BCrypt.gensalt());
		
		vo.setMember_pwd(pw1);
		vo.setMember_pwd_lock(pw2);
		
		return vo;
	}
	//��ȸ�� ����
	public NonMemberVO password_Lock_non(NonMemberVO vo)throws Exception{
		String pw1 = "";
		String pw2 = "";
		
		sha = SHA256.getInsatnce();
		
		pw1 = sha.getSha256(vo.getNonmember_pwd().getBytes());
		
		pw2 = BCrypt.hashpw(pw1, BCrypt.gensalt());
		
		vo.setNonmember_pwd(pw1);
		vo.setNonmember_pwd_lock(pw2);
		
		return vo;
	}
	
	public MemberVO password_Confirm(MemberVO vo , String password) throws Exception {
		String pw = "";
		
		sha = SHA256.getInsatnce();
		
		pw = sha.getSha256(password.getBytes());
		
		//System.out.println(pw);
		
		if(vo.getMember_pwd().equals(pw)) {
			
			if(BCrypt.hashpw(pw, vo.getMember_pwd_lock()).equals(vo.getMember_pwd_lock())) {
				return vo;//��ġ�Ѵٸ� ������� ���� return
			}
		}else {}
		
		
		return new MemberVO();//��й�ȣ�� ��ġ���������� ���� �ʱ�ȭ ���Ѽ� return
	}
	
	public NonMemberVO password_Confirm_non(NonMemberVO vo , String password) throws Exception {
		String pw = "";
		
		sha = SHA256.getInsatnce();
		
		pw = sha.getSha256(password.getBytes());
		
		if(vo.getNonmember_pwd().equals(pw)) {
			
			if(BCrypt.hashpw(pw, vo.getNonmember_pwd_lock()).equals(vo.getNonmember_pwd_lock())) {
				return vo;//��ġ�Ѵٸ� ������� ���� return
			}
		}else {}
		
		
		return new NonMemberVO();//��й�ȣ�� ��ġ���������� ���� �ʱ�ȭ ���Ѽ� return
	}
}
