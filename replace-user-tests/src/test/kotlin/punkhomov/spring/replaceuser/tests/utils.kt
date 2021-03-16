package punkhomov.spring.replaceuser.tests

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails

fun userBuild(block: User.UserBuilder.() -> Unit): UserDetails {
    val userBuilder = User.builder()
    block.invoke(userBuilder)
    return userBuilder.build()
}