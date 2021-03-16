package punkhomov.spring.replaceuser.tests

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import punkhomov.spring.replaceuser.ReplaceUserFilter
import punkhomov.spring.replaceuser.tests.SharedConfig.ANONYMOUS_PRINCIPAL
import punkhomov.spring.replaceuser.tests.SharedConfig.EXISTS_USERNAME
import punkhomov.spring.replaceuser.tests.SharedConfig.HTTP_METHOD
import punkhomov.spring.replaceuser.tests.SharedConfig.NOT_EXISTS_USERNAME
import punkhomov.spring.replaceuser.tests.SharedConfig.REFERER_ATTRIBUTE
import punkhomov.spring.replaceuser.tests.SharedConfig.REFERER_URL
import punkhomov.spring.replaceuser.tests.SharedConfig.REPLACE_URL
import punkhomov.spring.replaceuser.tests.SharedConfig.USERNAME_PARAMETER
import punkhomov.spring.replaceuser.tests.SharedConfig.USER_1

class ReplaceUserFilterWebmvc {
    private val session = MockHttpSession()
    private val request = MockHttpServletRequest(HTTP_METHOD.name, REPLACE_URL).apply {
        session = this@ReplaceUserFilterWebmvc.session
    }
    private val response = MockHttpServletResponse()
    private val filterChain = MockFilterChain()
    private val filter = replaceUserFilter()
    private var exception: Exception? = null

    @Test
    fun doFilter_SupplyExistsUsername_CreatesUserAuthentication() {
        request.addParameter(USERNAME_PARAMETER, EXISTS_USERNAME)

        filter.doFilter(request, response, filterChain)

        Assertions.assertEquals(
            EXISTS_USERNAME, SecurityContextHolder.getContext().authentication.name
        )
    }

    @Test
    fun doFilter_SupplyEmptyUsername_CreatesAnonymousAuthentication() {
        request.addParameter(USERNAME_PARAMETER, "")

        filter.doFilter(request, response, filterChain)

        Assertions.assertEquals(
            ANONYMOUS_PRINCIPAL,
            SecurityContextHolder.getContext().authentication.principal
        )
    }

    @Test
    fun doFilter_SupplyNotExistsUsername_ProducesUsernameNotFoundException() {
        request.addParameter(USERNAME_PARAMETER, NOT_EXISTS_USERNAME)

        filter.doFilter(request, response, filterChain)

        Assertions.assertEquals(UsernameNotFoundException::class.java, exception?.javaClass)
    }

    @Test
    fun doFilter_SuccessReplace_SavesRefererHeader() {
        request.addParameter(USERNAME_PARAMETER, EXISTS_USERNAME)
        request.addHeader("referer", REFERER_URL)

        filter.doFilter(request, response, filterChain)

        val refererAttribute = session.getAttribute(REFERER_ATTRIBUTE)
        Assertions.assertEquals(REFERER_URL, refererAttribute)
    }

    @Test
    fun doFilter_FailureReplace_DontSavesRefererHeader() {
        request.addParameter(USERNAME_PARAMETER, NOT_EXISTS_USERNAME)
        request.addHeader("referer", REFERER_URL)

        filter.doFilter(request, response, filterChain)

        val refererAttribute = session.getAttribute(REFERER_ATTRIBUTE)
        Assertions.assertEquals(null, refererAttribute)
    }

    private fun replaceUserFilter(): ReplaceUserFilter {
        return with(ReplaceUserFilter.Config()) {
            replaceUrl = REPLACE_URL
            httpMethod = HTTP_METHOD
            usernameParameter = USERNAME_PARAMETER
            successHandler = successHandlerImpl()
            failureHandler = failureHandlerImpl()
            userDetailsService = inMemoryUserDetailsManager()
            anonymousPrincipal = ANONYMOUS_PRINCIPAL
            refererAttributeName = REFERER_ATTRIBUTE

            ReplaceUserFilter(this)
        }
    }

    private fun successHandlerImpl(): AuthenticationSuccessHandler {
        return AuthenticationSuccessHandler { _, _, authentication ->
        }
    }

    private fun failureHandlerImpl(): AuthenticationFailureHandler {
        return AuthenticationFailureHandler { _, _, exception ->
            this.exception = exception
        }
    }

    private fun inMemoryUserDetailsManager(): UserDetailsService {
        return InMemoryUserDetailsManager().apply {
            createUser(USER_1)
        }
    }
}