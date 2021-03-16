package punkhomov.spring.replaceuser.tests

import org.springframework.http.HttpMethod

object SharedConfig {
    val HTTP_METHOD = HttpMethod.POST
    const val REPLACE_URL = "/replace"
    const val USERNAME_PARAMETER = "username"
    const val ANONYMOUS_PRINCIPAL = "__anonymous__"
    const val REFERER_ATTRIBUTE = "REFERER_ATTRIBUTE"

    const val EXISTS_USERNAME = "replaceTo"
    const val NOT_EXISTS_USERNAME = "NOT_EXISTS_USERNAME"
    const val REFERER_URL = "https://example.com/"

//    val SECURITY_CONTEXT_KEY = SecurityContext::class.java

    val USER_1 = userBuild {
        username(EXISTS_USERNAME)
        password("{noop}$EXISTS_USERNAME")
        roles("USER")
    }
}
