/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.identity.remote.userstore;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.um.ws.api.WSUserStoreManager;
import org.wso2.carbon.user.api.*;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;
import org.wso2.carbon.user.core.tenant.Tenant;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.identity.remote.userstore.internal.ConfigurationContextUtil;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class WSO2RemoteUserStoreManger implements UserStoreManager {

    private static final Log log = LogFactory.getLog(WSO2RemoteUserStoreManger.class);
    public static final String SERVER_URLS = "serverUrls";
    public static final String REMOTE_USER_NAME = "remoteUserName";
    public static final String PASSWORD = "password";
    private WSUserStoreManager remoteUserStore;
    private RealmConfiguration realmConfig;
    private UserStoreManager secondaryUserStoreManager;

    public WSO2RemoteUserStoreManger() {

    }

    /**
     * @param realmConfig
     * @param properties
     * @throws Exception
     */
    public WSO2RemoteUserStoreManger(RealmConfiguration realmConfig, Map properties)
            throws Exception {

        ConfigurationContext configurationContext = ConfigurationContextUtil.getInstance().getContext();

        String serverUrl = realmConfig.getUserStoreProperty(SERVER_URLS);


        remoteUserStore = new WSUserStoreManager(
                realmConfig.getUserStoreProperty(REMOTE_USER_NAME),
                realmConfig.getUserStoreProperty(PASSWORD), serverUrl,
                configurationContext);

        if (log.isDebugEnabled()) {
            log.debug("Remote WSO2 Server for User Management : " + serverUrl);
        }

        this.realmConfig = realmConfig;

    }

    /**
     *
     */

    @Override
    public Properties getDefaultUserStoreProperties() {
        Properties properties = new Properties();
        Property[] mandatoryProperties = null;
        Property[] optionalProperties = null;
        Property remoteServerUserName = new Property(
                REMOTE_USER_NAME,
                "",
                "Remote Sever Username#Name of a user from the remote server, having enough privileges for user management",
                null);
        Property password = new Property(PASSWORD, "",
                "Remote Server Password#The password correspoing to the remote server " +
                        "username#encrypt",
                null);
        Property serverUrls = new Property(
                SERVER_URLS,
                "",
                "Remote Server URL #Remote server URL. e.g.: https://ca-datacenter/services",
                null);
        Property disabled = new Property("Disabled", "false", "Disabled#Check to disable the user store", null);

        Property passwordJavaScriptRegEx = new Property(
                UserStoreConfigConstants.passwordJavaScriptRegEx, "^[\\S]{5,30}$",
                "Password RegEx (Javascript)#"
                        + UserStoreConfigConstants.passwordJavaScriptRegExDescription, null);
        Property usernameJavaScriptRegEx = new Property(
                UserStoreConfigConstants.usernameJavaScriptRegEx, "^[\\S]{3,30}$",
                "Username RegEx (Javascript)#"
                        + UserStoreConfigConstants.usernameJavaRegExDescription, null);
        Property roleNameJavaScriptRegEx = new Property(
                UserStoreConfigConstants.roleNameJavaScriptRegEx, "^[\\S]{3,30}$",
                "Role Name RegEx (Javascript)#"
                        + UserStoreConfigConstants.roleNameJavaScriptRegExDescription, null);

        mandatoryProperties = new Property[]{remoteServerUserName, password, serverUrls, passwordJavaScriptRegEx,
                usernameJavaScriptRegEx, roleNameJavaScriptRegEx};
        optionalProperties = new Property[]{disabled};

        properties.setOptionalProperties(optionalProperties);
        properties.setMandatoryProperties(mandatoryProperties);
        return properties;
    }

    /**
     *
     */
    @Override
    public boolean isExistingRole(String roleName, boolean isShared)
            throws org.wso2.carbon.user.api.UserStoreException {
        boolean rolesExists = false;
        try {
            rolesExists = remoteUserStore.isExistingRole(roleName, isShared);
        } catch (UserStoreException e) {
            log.error("Failed to check role " + roleName, e);
            throw e;
        }
        return rolesExists;
    }

    @Override
    public void addRole(String roleName, String[] userList, Permission[] permissions,
                        boolean isSharedRole) throws org.wso2.carbon.user.api.UserStoreException {

        try {
            remoteUserStore.addRole(roleName, userList, permissions, isSharedRole);
        } catch (UserStoreException e) {
            log.error("Failed to add role " + roleName, e);
            throw e;


        }


    }

    @Override
    public void addRole(String roleName, String[] userList, Permission[] permissions)
            throws org.wso2.carbon.user.api.UserStoreException {
        try {
            remoteUserStore.addRole(roleName, userList, permissions);
        } catch (UserStoreException e) {
            log.error("Failed to add role " + roleName, e);
            throw e;


        }
    }

    @Override
    public Map<String, String> getProperties(org.wso2.carbon.user.api.Tenant tenant)
            throws org.wso2.carbon.user.api.UserStoreException {
        Map<String, String> properties = new HashMap<String, String>();
        try {
            properties = remoteUserStore.getProperties(tenant);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Failed to get props from tenant " + tenant.getDomain(), e);
            throw e;
        }
        return properties;
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        // WSO2RemoteUserStoreManger does not support multiple profiles.
        return false;
    }

    @Override
    public void addRememberMe(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException {
        // WSO2RemoteUserStoreManger does not support remember-me..
    }

    @Override
    public boolean isValidRememberMeToken(String userName, String token)
            throws org.wso2.carbon.user.api.UserStoreException {
        // WSO2RemoteUserStoreManger does not support remember-me..
        return false;
    }

    @Override
    public ClaimManager getClaimManager() throws org.wso2.carbon.user.api.UserStoreException {
        return remoteUserStore.getClaimManager();
    }

    @Override
    public boolean isSCIMEnabled() throws org.wso2.carbon.user.api.UserStoreException {
        // WSO2RemoteUserStoreManger does not support SCIM.
        return false;
    }

    @Override
    public boolean authenticate(String userName, Object credential) throws UserStoreException {
        return this.remoteUserStore.authenticate(userName, credential);
    }

    @Override
    public String[] listUsers(String filter, int maxItemLimit) throws UserStoreException {

        String[] users = null;

        try {
            users = remoteUserStore.listUsers(filter, maxItemLimit);
        } catch (UserStoreException e) {
            log.error("Failed to get user list ", e);
            throw e;
        }

        if (users == null) {
            users = new String[0];
        }

        return users;
    }

    @Override
    public boolean isExistingUser(String userName) throws UserStoreException {
        boolean usersExists = false;
        try {
            usersExists = remoteUserStore.isExistingUser(userName);
        } catch (UserStoreException e) {

            log.error("Failed to check user " + userName, e);
            throw e;
        }
        return usersExists;
    }

    @Override
    public boolean isExistingRole(String roleName) throws UserStoreException {
        boolean roleExists = false;
        try {
            roleExists = remoteUserStore.isExistingRole(roleName);
        } catch (UserStoreException e) {

            log.error("Failed to check role " + roleName, e);
            throw e;
        }
        return roleExists;
    }

    @Override
    public String[] getRoleNames() throws UserStoreException {

        String[] roles = new String[0];

        try {
            roles = remoteUserStore.getRoleNames();
        } catch (UserStoreException e) {
            log.error("Failed to get role list ", e);
            throw e;
        }

        return roles;
    }

    @Override
    public String[] getRoleNames(boolean noHybridRoles) throws UserStoreException {
        String[] roles = new String[0];

        try {
            roles = remoteUserStore.getRoleNames(noHybridRoles);
        } catch (UserStoreException e) {
            log.error("Failed to get role list ", e);
            throw e;
        }

        return roles;
    }

    @Override
    public String[] getProfileNames(String userName) throws UserStoreException {

        String[] profileNames = new String[0];

        try {
            profileNames = remoteUserStore.getProfileNames(userName);
        } catch (UserStoreException e) {
            log.error("Failed to get profiles of " + userName, e);
            throw e;
        }
        return profileNames;
    }

    @Override
    public String[] getRoleListOfUser(String userName) throws UserStoreException {
        String[] roles = new String[0];

        try {
            roles = remoteUserStore.getRoleListOfUser(userName);
        } catch (UserStoreException e) {
            log.error("Failed to get role list of " + userName, e);
            throw e;
        }

        return roles;
    }

    @Override
    public String[] getUserListOfRole(String roleName) throws UserStoreException {
        String[] users = new String[0];

        try {
            users = remoteUserStore.getUserListOfRole(roleName);
        } catch (UserStoreException e) {
            log.error("Failed to get user list of " + roleName, e);
            throw e;
        }
        return users;
    }

    @Override
    public String getUserClaimValue(String userName, String claim, String profileName)
            throws UserStoreException {
        String claimValue = null;
        try {
            claimValue = remoteUserStore.getUserClaimValue(userName, claim, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to get claim list of " + userName, e);
            throw e;
        }
        return claimValue;
    }

    @Override
    public Map<String, String> getUserClaimValues(String userName, String[] claims,
                                                  String profileName) throws UserStoreException {
        Map<String, String> claimValue = new HashMap<String, String>();

        try {
            claimValue = remoteUserStore.getUserClaimValues(userName, claims, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to get claim list of " + userName, e);
            throw e;
        }
        return claimValue;
    }

    /**
     *
     */
    @Override
    public Claim[] getUserClaimValues(String userName, String profileName)
            throws UserStoreException {
        Claim[] claim = new Claim[0];
        try {
            claim = remoteUserStore.getUserClaimValues(userName, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to get claim list of " + userName, e);
            throw e;
        }
        return claim;
    }

    /**
     *
     */
    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        String[] profileNames = new String[0];
        try {
            profileNames = remoteUserStore.getAllProfileNames();
        } catch (UserStoreException e) {
            log.error("Failed to get profiles ", e);
            throw e;
        }
        return profileNames;
    }

    @Override
    public boolean isReadOnly() throws UserStoreException {
        boolean readOnly = false;
        try {
            readOnly = remoteUserStore.isReadOnly();
        } catch (UserStoreException e) {
            log.error("Failed to check isReadOnly", e);
            throw e;
        }
        return readOnly;
    }

    @Override
    public void addUser(String userName, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName) throws UserStoreException {


        try {
            remoteUserStore.addUser(userName, credential, roleList, claims, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to add user " + userName, e);
            throw e;
        }

    }

    @Override
    public void addUser(String userName, Object credential, String[] roleList,
                        Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {
        try {
            remoteUserStore.addUser(userName, credential, roleList, claims, profileName, requirePasswordChange);
        } catch (UserStoreException e) {
            log.error("Failed to add user " + userName, e);
            throw e;
        }
    }

    @Override
    public void updateCredential(String userName, Object newCredential, Object oldCredential)
            throws UserStoreException {

        try {
            remoteUserStore.updateCredential(userName, newCredential, oldCredential);
        } catch (UserStoreException e) {
            log.error("Failed to update credential " + userName, e);
            throw e;
        }

    }

    @Override
    public void updateCredentialByAdmin(String userName, Object newCredential)
            throws UserStoreException {
        try {
            remoteUserStore.updateCredentialByAdmin(userName, newCredential);
        } catch (UserStoreException e) {
            log.error("Failed to update credential " + userName, e);
            throw e;
        }
    }

    @Override
    public void deleteUser(String userName) throws UserStoreException {

        String domainAwareUserName = UserCoreUtil.removeDomainFromName(userName);

        try {
            remoteUserStore.deleteUser(domainAwareUserName);
        } catch (UserStoreException e) {
            log.error("Failed to delete user " + userName, e);
            throw e;
        }

    }

    @Override
    public void deleteRole(String roleName) throws UserStoreException {

        String domainAwareRoleName = UserCoreUtil.removeDomainFromName(roleName);


        try {
            remoteUserStore.deleteUser(domainAwareRoleName);
        } catch (UserStoreException e) {
            log.error("Failed to delete user " + roleName, e);
            throw e;
        }
    }

    @Override
    public void updateUserListOfRole(String roleName, String[] deletedUsers, String[] newUsers)
            throws UserStoreException {

        try {
            remoteUserStore.updateUserListOfRole(roleName, deletedUsers, newUsers);
        } catch (UserStoreException e) {
            log.error("Failed to update user list of role " + roleName, e);
            throw e;
        }

    }

    @Override
    public void updateRoleListOfUser(String userName, String[] deletedRoles, String[] newRoles)
            throws UserStoreException {

        try {
            remoteUserStore.updateRoleListOfUser(userName, deletedRoles, newRoles);
        } catch (UserStoreException e) {
            log.error("Failed to update role list of user " + userName, e);
            throw e;
        }
    }

    @Override
    public void setUserClaimValue(String userName, String claimURI, String claimValue,
                                  String profileName) throws UserStoreException {

        try {
            remoteUserStore.setUserClaimValue(userName, claimURI, claimValue,
                    profileName);
        } catch (UserStoreException e) {
            log.error("Failed to srt claim of user " + userName, e);
            throw e;
        }

    }

    @Override
    public void setUserClaimValues(String userName, Map<String, String> claims, String profileName)
            throws UserStoreException {

        try {
            remoteUserStore.setUserClaimValues(userName, claims, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to set claim of user " + userName, e);
            throw e;
        }

    }

    @Override
    public void deleteUserClaimValue(String userName, String claimURI, String profileName)
            throws UserStoreException {
        try {
            remoteUserStore.deleteUserClaimValue(userName, claimURI, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to delete claim of user " + userName, e);
            throw e;
        }
    }

    @Override
    public void deleteUserClaimValues(String userName, String[] claims, String profileName)
            throws UserStoreException {
        try {
            remoteUserStore.deleteUserClaimValues(userName, claims, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to delete claims of user " + userName, e);
            throw e;
        }
    }

    @Override
    public String[] getHybridRoles() throws UserStoreException {
        String[] roles = new String[0];
        try {
            roles = remoteUserStore.getHybridRoles();
        } catch (UserStoreException e) {
            log.error("Failed to get hybrid roles ", e);
            throw e;
        }

        return roles;
    }

    @Override
    public String[] getAllSecondaryRoles() throws UserStoreException {
        String[] roles = new String[0];

        try {
            roles = remoteUserStore.getAllSecondaryRoles();
        } catch (UserStoreException e) {
            log.error("Failed to get secondary roles ", e);
            throw e;

        }

        return roles;
    }

    @Override
    public Date getPasswordExpirationTime(String username) throws UserStoreException {
        Date date = null;
        try {
            date = remoteUserStore.getPasswordExpirationTime(username);
        } catch (UserStoreException e) {
            log.error("Failed to get password Expiration Time of " + username, e);
            throw e;

        }
        return date;
    }

    @Override
    public int getUserId(String username) throws UserStoreException {
        int userId = -1;
        try {
            userId = remoteUserStore.getUserId(username);
        } catch (UserStoreException e) {
            log.error("Failed to get userid of  " + username, e);
            throw e;
        }
        return userId;
    }

    @Override
    public int getTenantId(String username) throws UserStoreException {
        int tenantId = -1;
        try {
            tenantId = remoteUserStore.getTenantId(username);
        } catch (UserStoreException e) {
            log.error("Failed to et tenantId of " + username, e);
            throw e;
        }
        return tenantId;
    }

    @Override
    public int getTenantId() throws UserStoreException {
        int tenantId = -1;
        try {
            tenantId = remoteUserStore.getTenantId();
        } catch (UserStoreException e) {
            log.error("Failed to get tenantId", e);
            throw e;
        }
        return tenantId;
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        Map<String, String> properties = new HashMap<String, String>();
        try {
            properties = remoteUserStore.getProperties(tenant);
        } catch (UserStoreException e) {

            log.error("Failed to get props  of " + tenant.getDomain(), e);
            throw e;
        }
        return properties;
    }

    @Override
    public void updateRoleName(String roleName, String newRoleName) throws UserStoreException {

        try {
            remoteUserStore.updateRoleName(roleName, newRoleName);
        } catch (UserStoreException e) {
            log.error("Failed to update role name of " + roleName, e);
            throw e;
        }

    }

    @Override
    public boolean isBulkImportSupported() throws UserStoreException {
        return false;
    }

    @Override
    public String[] getUserList(String claim, String claimValue, String profileName)
            throws UserStoreException {
        String[] users = new String[0];
        try {
            users = remoteUserStore.getUserList(claim, claimValue, profileName);
        } catch (UserStoreException e) {
            log.error("Failed to get user list", e);
            throw e;
        }
        return users;
    }

    @Override
    public UserStoreManager getSecondaryUserStoreManager() {
        return secondaryUserStoreManager;
    }

    @Override
    public void setSecondaryUserStoreManager(UserStoreManager userStoreManager) {
        this.secondaryUserStoreManager = userStoreManager;

    }

    @Override
    public UserStoreManager getSecondaryUserStoreManager(String userDomain) {
        return secondaryUserStoreManager;
    }

    @Override
    public void addSecondaryUserStoreManager(String userDomain, UserStoreManager userStoreManager) {
        return;
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return realmConfig;
    }

}
