package punkhomov.spring.replaceuser.tests

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.mock.web.server.MockWebSession
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.server.WebFilterChain
import org.springframework.web.server.WebSession
import punkhomov.spring.replaceuser.ReplaceUserWebFilter
import punkhomov.spring.replaceuser.tests.SharedConfig.ANONYMOUS_PRINCIPAL
import punkhomov.spring.replaceuser.tests.SharedConfig.EXISTS_USERNAME
import punkhomov.spring.replaceuser.tests.SharedConfig.HTTP_METHOD
import punkhomov.spring.replaceuser.tests.SharedConfig.NOT_EXISTS_USERNAME
import punkhomov.spring.replaceuser.tests.SharedConfig.REFERER_ATTRIBUTE
import punkhomov.spring.replaceuser.tests.SharedConfig.REFERER_URL
import punkhomov.spring.replaceuser.tests.SharedConfig.REPLACE_URL
import punkhomov.spring.replaceuser.tests.SharedConfig.USERNAME_PARAMETER
import punkhomov.spring.replaceuser.tests.SharedConfig.USER_1
import reactor.core.publisher.Mono
import reactor.test.StepVerifier
import reactor.test.StepVerifierOptions

class ReplaceUserFilterWebflux {
    private val session = MockWebSession()
    private val filter = replaceUserFilter()
    private val filterChain = WebFilterChain { Mono.empty() }
    private var exception: Exception? = null

    @Test
    fun filter_SupplyExistsUsername_CreatesUserAuthentication() {
        val exchange = createExchange(session) {
            username(EXISTS_USERNAME)
        }

        StepVerifier.create(filter.filter(exchange, filterChain), createStepVerifierOptions())
            .verifyComplete()

        val securityContext = session.securityContext!!
        Assertions.assertEquals(EXISTS_USERNAME, securityContext.authentication.name)
    }

    @Test
    fun filter_SupplyEmptyUsername_CreatesAnonymousAuthentication() {
        val exchange = createExchange(session) {
            username()
        }

        StepVerifier.create(filter.filter(exchange, filterChain), createStepVerifierOptions())
            .verifyComplete()

        val securityContext = session.securityContext!!
        Assertions.assertEquals(ANONYMOUS_PRINCIPAL, securityContext.authentication.principal)
    }

    @Test
    fun filter_SupplyBadUsername_ProducesError() {
        val exchange = createExchange(session) {
            username(NOT_EXISTS_USERNAME)
        }

        StepVerifier.create(filter.filter(exchange, filterChain), createStepVerifierOptions())
            .verifyComplete()

        Assertions.assertEquals(AuthenticationCredentialsNotFoundException::class, exception?.let { it::class })
    }

    @Test
    fun filterReferer_SuccessReplace_SavesRefererHeader() {
        val exchange = createExchange(session) {
            header("referer", REFERER_URL)
            username(EXISTS_USERNAME)
        }

        StepVerifier.create(filter.filter(exchange, filterChain), createStepVerifierOptions())
            .verifyComplete()

        val refererAttribute: String? = session.getAttribute<String>(REFERER_ATTRIBUTE)
        println(refererAttribute)
        Assertions.assertEquals(REFERER_URL, refererAttribute)
    }

    @Test
    fun filterReferer_FailureReplace_DontSavesRefererHeader() {
        val exchange = createExchange(session) {
            header("referer", REFERER_URL)
            username(NOT_EXISTS_USERNAME)
        }

        StepVerifier.create(filter.filter(exchange, filterChain), createStepVerifierOptions())
            .verifyComplete()

        val refererAttribute: String? = session.getAttribute(REFERER_ATTRIBUTE)
        println(refererAttribute)
        Assertions.assertEquals(null, refererAttribute)
    }


    private fun MockServerHttpRequest.BodyBuilder.username(value: String? = null): MockServerHttpRequest {
        contentType(MediaType.APPLICATION_FORM_URLENCODED)
        return body("$USERNAME_PARAMETER=${value ?: ""}")
    }

    private val WebSession.securityContext get() = getAttribute<SecurityContext>("SPRING_SECURITY_CONTEXT")

    private fun createExchange(
        session: WebSession,
        httpMethod: HttpMethod = HttpMethod.POST,
        url: String = REPLACE_URL,
        uriVars: Collection<Any> = emptyList(),
        serverRequest: MockServerHttpRequest.BodyBuilder.() -> MockServerHttpRequest = { build() }
    ): MockServerWebExchange {
        val request = serverRequest.invoke(MockServerHttpRequest.method(httpMethod, url, uriVars))

        return MockServerWebExchange.builder(request)
            .session(session)
            .build()
    }

    private fun createStepVerifierOptions(): StepVerifierOptions {
        val securityContext = SecurityContextImpl(
            AnonymousAuthenticationToken(
                "test", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
            )
        )

        return StepVerifierOptions.create()
            .withInitialContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
    }

    private fun replaceUserFilter(): ReplaceUserWebFilter {
        return with(ReplaceUserWebFilter.Config()) {
            replaceUrl = REPLACE_URL
            httpMethod = HTTP_METHOD
            usernameParameter = USERNAME_PARAMETER
            successHandler = successHandlerImpl()
            failureHandler = failureHandlerImpl()
            userDetailsService = inMemoryUserDetailsManager()
            anonymousPrincipal = ANONYMOUS_PRINCIPAL
            refererAttributeName = REFERER_ATTRIBUTE

            ReplaceUserWebFilter(this)
        }
    }

    private fun successHandlerImpl(): ServerAuthenticationSuccessHandler {
        return ServerAuthenticationSuccessHandler { _: WebFilterExchange, _: Authentication ->
            Mono.empty()
        }
    }

    private fun failureHandlerImpl(): ServerAuthenticationFailureHandler {
        return ServerAuthenticationFailureHandler { _: WebFilterExchange, ex: Exception ->
            this.exception = ex
            Mono.empty()
        }
    }

    private fun inMemoryUserDetailsManager(): MapReactiveUserDetailsService {
        return MapReactiveUserDetailsService(listOf(USER_1))
    }
}