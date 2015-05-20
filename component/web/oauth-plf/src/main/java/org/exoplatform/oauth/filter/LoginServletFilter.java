/*
 * Copyright (C) 2015 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.exoplatform.oauth.filter;

import org.exoplatform.commons.utils.ListAccess;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.Query;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserProfile;
import org.exoplatform.services.organization.UserProfileHandler;
import org.exoplatform.services.organization.UserStatus;
import org.exoplatform.services.resources.ResourceBundleService;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Credential;
import org.exoplatform.services.security.PasswordCredential;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.web.application.AbstractApplicationMessage;
import org.exoplatform.web.filter.Filter;
import org.exoplatform.web.security.AuthenticationRegistry;
import org.exoplatform.webui.exception.MessageException;
import org.exoplatform.webui.form.UIFormStringInput;
import org.exoplatform.webui.form.validator.PersonalNameValidator;
import org.exoplatform.webui.form.validator.UserConfigurableValidator;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.exception.OAuthException;
import org.gatein.security.oauth.exception.OAuthExceptionCode;
import org.gatein.security.oauth.spi.OAuthPrincipal;
import org.gatein.security.oauth.spi.OAuthProviderType;
import javax.security.auth.login.LoginException;
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * @author <a href="mailto:tuyennt@exoplatform.com">Tuyen Nguyen The</a>.
 */
public class LoginServletFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        req.setCharacterEncoding("UTF-8");

        // User already loggedIn
        if (req.getRemoteUser() != null) {
            chain.doFilter(request, response);
            return;
        }

        //
        req.getSession().removeAttribute(OAuthConstants.ATTRIBUTE_EXCEPTION_OAUTH);

        PortalContainer container = PortalContainer.getCurrentInstance(request.getServletContext());
        AuthenticationRegistry authReg = container.getComponentInstanceOfType(AuthenticationRegistry.class);
        ResourceBundleService service = container.getComponentInstanceOfType(ResourceBundleService.class);
        ResourceBundle bundle = service.getResourceBundle(service.getSharedResourceBundleNames(), req.getLocale()) ;
        MessageResolver messageResolver = new MessageResolver(bundle);
        ServletContext context = container.getPortalContext();

        User authenticated = (User)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_FOR_JAAS);
        if (authenticated != null) {
            chain.doFilter(request, response);
            return;
        }

        User oauthAuthenticatedUser = (User) authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
        User detectedUser = (User)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);
        if (oauthAuthenticatedUser == null) {
            // Do normal login
            chain.doFilter(request, response);
            return;
        }

        request.setAttribute("portalUser", oauthAuthenticatedUser);
        if (detectedUser != null) {
            request.setAttribute("detectedUser", detectedUser);
        }


        if(processCancelOauth(req, res, authReg)) {
            return;
        }

        if(processConfirmExistingAccount(req, res, messageResolver, authReg, container)) {
            return;
        }

        if(processCreateNewAccount(req, res, messageResolver, container, authReg, oauthAuthenticatedUser)) {
            return;
        }

        String createNewAccount = req.getParameter("create_new_account");
        if (createNewAccount == null) {
            createNewAccount = (String)req.getSession().getAttribute("__oauth_create_new_account");
        } else {
            req.getSession().setAttribute("__oauth_create_new_account", createNewAccount);
        }
        if(detectedUser != null && createNewAccount == null) {
            RequestDispatcher invitation = context.getRequestDispatcher("/login/jsp/oauth_invitation.jsp");
            if(invitation != null) {
                invitation.forward(req, res);
                return;
            }
        } else {
            RequestDispatcher register = context.getRequestDispatcher("/login/jsp/oauth_register.jsp");
            if(register != null) {
                register.forward(req, res);
                return;
            }
        }

        chain.doFilter(req, res);
    }

    private void sendRedirect(String url, HttpServletRequest req, HttpServletResponse res) throws IOException {
        if(url != null) {
            res.sendRedirect(res.encodeRedirectURL(url));
        } else {
            res.sendRedirect(req.getServletPath());
        }
    }

    private boolean processCancelOauth(HttpServletRequest req, HttpServletResponse res, AuthenticationRegistry authReg) throws IOException {
        String cancelOauth = req.getParameter("cancel_oauth");
        if (cancelOauth != null && "1".equalsIgnoreCase(cancelOauth)) {
            req.getSession().removeAttribute("__oauth_create_new_account");
            authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_OAUTH_PRINCIPAL);
            authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
            authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);

            //. Redirect to last URL
            String registrationURL = (String)req.getSession().getAttribute(OAuthConstants.ATTRIBUTE_URL_TO_REDIRECT_AFTER_LINK_SOCIAL_ACCOUNT);
            if(registrationURL == null) {
                registrationURL = req.getServletPath();
            }
            sendRedirect(registrationURL, req, res);
            return true;
        }
        return false;
    }

    private boolean processConfirmExistingAccount(HttpServletRequest req, HttpServletResponse res, MessageResolver bundle, AuthenticationRegistry authReg, PortalContainer container) throws IOException, ServletException {
        String confirm = req.getParameter("confirm_existing_account");
        if(confirm == null) {
            return false;
        }

        String username;
        User detectedUser = (User)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);
        if(detectedUser != null) {
            username = detectedUser.getUserName();
        } else {
            req.setAttribute("invitationConfirmError", bundle.resolve("UIOAuthInvitationForm.message.not-in-oauth-login"));
            container.getPortalContext().getRequestDispatcher("/login/jsp/oauth_invitation.jsp").forward(req, res);
            return true;
        }

        String password = req.getParameter("password");
        Credential[] credentials =
                new Credential[]{new UsernameCredential(username), new PasswordCredential(password)};
        try {
            Authenticator authenticator = container.getComponentInstanceOfType(Authenticator.class);
            OrganizationService orgService = container.getComponentInstanceOfType(OrganizationService.class);
            String user = authenticator.validateUser(credentials);
            if(user != null && !user.isEmpty()) {
                //Update authentication
                OAuthPrincipal principal = (OAuthPrincipal)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_OAUTH_PRINCIPAL);
                OAuthProviderType providerType = principal.getOauthProviderType();

                UserProfileHandler profileHandler = orgService.getUserProfileHandler();
                UserProfile newUserProfile = profileHandler.findUserProfileByName(user);
                if (newUserProfile == null) {
                    newUserProfile = orgService.getUserProfileHandler().createUserProfileInstance(user);
                }

                newUserProfile.setAttribute(providerType.getUserNameAttrName(), principal.getUserName());
                profileHandler.saveUserProfile(newUserProfile, true);

                //. Redirect to last URL
                authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
                authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);
                String registrationURL = (String)req.getSession().getAttribute(OAuthConstants.ATTRIBUTE_URL_TO_REDIRECT_AFTER_LINK_SOCIAL_ACCOUNT);
                if(registrationURL == null) {
                    registrationURL = req.getServletPath();
                }
                res.sendRedirect(res.encodeRedirectURL(registrationURL));
                return true;
            }
        } catch (LoginException ex) {
            req.setAttribute("invitationConfirmError", bundle.resolve("UIOAuthInvitationForm.message.loginFailure"));
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
            req.setAttribute("invitationConfirmError", bundle.resolve("UIOAuthInvitationForm.message.loginFailure"));
        }

        container.getPortalContext().getRequestDispatcher("/login/jsp/oauth_invitation.jsp").forward(req, res);

        return true;
    }

    private boolean processCreateNewAccount(HttpServletRequest req, HttpServletResponse res, MessageResolver bundle, PortalContainer container, AuthenticationRegistry authReg, User portalUser) throws IOException {
        String signup = req.getParameter("oauth_do_register_new");
        if(signup == null) {
            return false;
        }

        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String password2 = req.getParameter("password2");
        String firstName = req.getParameter("firstName");
        String lastName = req.getParameter("lastName");
        String displayName = req.getParameter("displayName");
        String email = req.getParameter("email");

        portalUser.setUserName(username);
        portalUser.setPassword(password);
        portalUser.setFirstName(firstName);
        portalUser.setLastName(lastName);
        portalUser.setDisplayName(displayName);
        portalUser.setEmail(email);

        List<String> errors = new ArrayList<String>();
        Set<String> errorFields = new HashSet<String>();
        OrganizationService orgService = container.getComponentInstanceOfType(OrganizationService.class);

        validateUser(portalUser, password2, orgService, bundle, errors, errorFields);
        if(errors.size() > 0) {
            req.setAttribute("register_errors", errors);
            req.setAttribute("register_error_fields", errorFields);
            return false;
        }

        try {
            orgService.getUserHandler().createUser(portalUser, true);
            UserProfileHandler profileHandler = orgService.getUserProfileHandler();
            UserProfile newUserProfile = profileHandler.findUserProfileByName(portalUser.getUserName());
            if (newUserProfile == null) {
                newUserProfile = orgService.getUserProfileHandler().createUserProfileInstance(portalUser.getUserName());
            }
            OAuthPrincipal oauthPrincipal = (OAuthPrincipal)authReg.getAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_OAUTH_PRINCIPAL);
            newUserProfile.setAttribute(oauthPrincipal.getOauthProviderType().getUserNameAttrName(), oauthPrincipal.getUserName());

            try {
                profileHandler.saveUserProfile(newUserProfile, true);

                authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER);
                authReg.removeAttributeOfClient(req, OAuthConstants.ATTRIBUTE_AUTHENTICATED_PORTAL_USER_DETECTED);

                // Successfully to register new account
                res.sendRedirect(container.getPortalContext().getContextPath());
                return true;

            } catch (OAuthException gtnOAuthException) {
                // Show warning message if user with this facebookUsername (or googleUsername) already exists
                // NOTE: It could happen only in case of parallel registration of same oauth user from more browser windows
                if (gtnOAuthException.getExceptionCode() == OAuthExceptionCode.DUPLICATE_OAUTH_PROVIDER_USERNAME) {

                    // Drop new user
                    orgService.getUserHandler().removeUser(portalUser.getUserName(), true);

                    // Clear previous message about successful creation of user because we dropped him. Add message about duplicate oauth username
                    errors.add(bundle.resolve("UIAccountSocial.msg.failed-registration",
                            gtnOAuthException.getExceptionAttribute(OAuthConstants.EXCEPTION_OAUTH_PROVIDER_USERNAME),
                            gtnOAuthException.getExceptionAttribute(OAuthConstants.EXCEPTION_OAUTH_PROVIDER_NAME)));
                } else {
                    errors.add("Exception while create new account:" + gtnOAuthException.getMessage());
                }
                req.setAttribute("register_errors", errors);
                return false;
            }
        } catch (Exception ex) {
            errors.add("Exception while create new account" + ex.getMessage());
            req.setAttribute("register_errors", errors);
            return false;
        }
    }

    private void validateUser(User user, String password2, OrganizationService orgService, MessageResolver bundle, List<String> errorMessages, Set<String> errorFields) {
        //
        String username = user.getUserName();
        UserConfigurableValidator configurableValidator = new UserConfigurableValidator(UserConfigurableValidator.USERNAME, UserConfigurableValidator.DEFAULT_LOCALIZATION_KEY);
        try {
            configurableValidator.validate(new UIFormStringInput("username", username));
        } catch (Exception ex) {
            errorFields.add("username");
            if (ex instanceof MessageException) {
                MessageException mex = (MessageException)ex;
                AbstractApplicationMessage msg = mex.getDetailMessage();
                msg.setResourceBundle(bundle.getBundle());
                errorMessages.add(msg.getMessage());
            } else {
                errorMessages.add("User name is not valid");
            }
        }
        if (!errorFields.contains("username")) {
            try {
                if (orgService.getUserHandler().findUserByName(username, UserStatus.ANY) != null) {
                    errorFields.add("username");
                    errorMessages.add(bundle.resolve("UIAccountInputSet.msg.user-exist", username));
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        //
        String password = user.getPassword();
        if(password == null || password.isEmpty()) {
            errorMessages.add(bundle.resolve("EmptyFieldValidator.msg.empty-input", "password"));
            errorFields.add("password");
        } else if (password.length() < 6 || password.length() > 30) {
            errorMessages.add(bundle.resolve("StringLengthValidator.msg.length-invalid", "password", 6, 30));
            errorFields.add("password");
        }
        if(!password.equals(password2)) {
            errorMessages.add("UIAccountForm.msg.password-is-not-match");
            errorFields.add("password2");
        }

        PersonalNameValidator nameValidator = new PersonalNameValidator();
        String firstName = user.getFirstName();
        String lastName = user.getLastName();
        if(firstName != null && !firstName.isEmpty()) {
            try {
                nameValidator.validate(new UIFormStringInput("firstName", firstName));
            } catch (Exception e) {
                errorFields.add("firstName");
                if (e instanceof MessageException) {
                    MessageException mex = (MessageException)e;
                    AbstractApplicationMessage msg = mex.getDetailMessage();
                    msg.setResourceBundle(bundle.getBundle());
                    errorMessages.add(msg.getMessage());
                } else {
                    e.printStackTrace();
                }
            }
        }
        if(lastName != null && !lastName.isEmpty()) {
            try {
                nameValidator.validate(new UIFormStringInput("lastName", lastName));
            } catch (Exception e) {
                errorFields.add("lastName");
                if (e instanceof MessageException) {
                    MessageException mex = (MessageException)e;
                    AbstractApplicationMessage msg = mex.getDetailMessage();
                    msg.setResourceBundle(bundle.getBundle());
                    errorMessages.add(msg.getMessage());
                } else {
                    e.printStackTrace();
                }
            }
        }

        configurableValidator = new UserConfigurableValidator("displayname", UserConfigurableValidator.KEY_PREFIX + "displayname", false);
        String displayName = user.getDisplayName();
        try {
            configurableValidator.validate(new UIFormStringInput("displayName", displayName));
        } catch (Exception e) {
            errorFields.add("displayName");
            if (e instanceof MessageException) {
                MessageException mex = (MessageException)e;
                AbstractApplicationMessage msg = mex.getDetailMessage();
                msg.setResourceBundle(bundle.getBundle());
                errorMessages.add(msg.getMessage());
            } else {
                e.printStackTrace();
            }
        }


        //
        configurableValidator = new UserConfigurableValidator(UserConfigurableValidator.EMAIL);
        String email = user.getEmail();
        try {
            configurableValidator.validate(new UIFormStringInput("email", email));
        } catch (Exception ex) {
            errorFields.add("email");
            if (ex instanceof MessageException) {
                MessageException mex = (MessageException)ex;
                AbstractApplicationMessage msg = mex.getDetailMessage();
                msg.setResourceBundle(bundle.getBundle());
                errorMessages.add(msg.getMessage());
            } else {
                errorMessages.add("Email error");
            }
        }
        if (!errorFields.contains("email")) {
            try {
                Query query = new Query();
                query.setEmail(email);
                ListAccess<User> users = orgService.getUserHandler().findUsersByQuery(query, UserStatus.ANY);
                if (users != null && users.getSize() > 0) {
                    errorFields.add("email");
                    errorMessages.add(bundle.resolve("UIAccountInputSet.msg.email-exist", email));
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public static class MessageResolver {
        private final ResourceBundle bundle;

        public MessageResolver(ResourceBundle bundle) {
            this.bundle = bundle;
        }

        public String resolve(String key, Object... args) {
            try {
                String message = bundle.getString(key);
                if (message != null && args != null) {
                    for (int i = 0; i < args.length; i++) {
                        final Object messageArg = args[i];
                        if (messageArg != null) {
                            String arg = messageArg.toString();
                            message = message.replace("{" + i + "}", arg);
                        }
                    }
                }
                return message;
            } catch (Exception ex) {
                return key;
            }
        }

        public ResourceBundle getBundle() {
            return bundle;
        }
    }
}
