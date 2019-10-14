package com.luo.shiro.realm;

import com.luo.util.DecriptUtil;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

public class MyShiroRealm extends AuthorizingRealm {
	
	//这里因为没有调用后台，直接默认只有一个用户("luoguohui"，"123456")
	private static final String USER_NAME = "lidong";
	private static final String PASSWORD = "123456";  
	
	/* 
	 * 授权
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) { 
        Set<String> roleNames = new HashSet<String>();  
        Set<String> permissions = new HashSet<String>();  
        roleNames.add("admin");//添加角色
        permissions.add("view");  //添加权限
		permissions.add("loginsuccess.jhtml");
		permissions.add("newPage.jhtml");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo(roleNames);
        info.setStringPermissions(permissions);  
        return info;  
	}
	
	
	/* 
	 * 登录验证
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken authcToken) throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authcToken;
		if(token.getUsername().equals(USER_NAME)){
			return new SimpleAuthenticationInfo(USER_NAME, DecriptUtil.MD5(PASSWORD), getName());  
		}else{
			throw new AuthenticationException();  
		}
	}

}
