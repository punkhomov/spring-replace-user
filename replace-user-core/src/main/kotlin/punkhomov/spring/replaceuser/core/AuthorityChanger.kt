package punkhomov.spring.replaceuser.core

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

interface AuthorityChanger {
    fun modifyGrantedAuthorities(
        targetUser: UserDetails?,
        authoritiesToBeGranted: Collection<GrantedAuthority>
    ): Collection<GrantedAuthority>
}

