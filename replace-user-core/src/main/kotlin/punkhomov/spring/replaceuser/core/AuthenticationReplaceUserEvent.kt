package punkhomov.spring.replaceuser.core

import org.springframework.security.authentication.event.AbstractAuthenticationEvent
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails

class AuthenticationReplaceUserEvent(
    authentication: Authentication, val targetUser: UserDetails
) : AbstractAuthenticationEvent(authentication)