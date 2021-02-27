package punkhomov.spring.replaceuser.core

import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetailsChecker
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

class ReplaceUserFilterConfig {
    var replaceUrl: String? = null
    var httpMethod: HttpMethod = HttpMethod.POST
    var usernameParameter: String = "username"
    var refererUrlAttributeName: String? = null

    var successUrl: String? = null
    var failureUrl: String? = null
    var successHandler: AuthenticationSuccessHandler? = null
    var failureHandler: AuthenticationFailureHandler? = null

    var userDetailsService: UserDetailsService? = null
    var userDetailsChecker: UserDetailsChecker = AccountStatusUserDetailsChecker()

    var anonymousKey: String? = null
    var anonymousPrincipal: Any? = null
    var anonymousAuthorities: Collection<GrantedAuthority> =
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")

    var authorityChanger: AuthorityChanger? = null
}