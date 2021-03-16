package punkhomov.spring.replaceuser.core

import org.springframework.http.HttpMethod
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils

object ReplaceUserConstants {
    val DEFAULT_HTTP_METHOD = HttpMethod.POST

    const val DEFAULT_USERNAME_PARAMETER = "username"

    const val DEFAULT_ANONYMOUS_KEY = "ReplaceUser.Key"

    const val DEFAULT_ANONYMOUS_PRINCIPAL = "anonymousUser"

    val DEFAULT_ANONYMOUS_AUTHORITIES: Collection<GrantedAuthority> =
        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")

    const val REDIRECT_LOCATION_ATTRIBUTE_KEY = "punkhomov.spring.replaceuser.REDIRECT_LOCATION_ATTRIBUTE_KEY"
}