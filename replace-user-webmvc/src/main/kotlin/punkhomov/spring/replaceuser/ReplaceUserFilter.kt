package punkhomov.spring.replaceuser

import org.springframework.core.log.LogMessage
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsChecker
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.*
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.util.Assert
import org.springframework.web.filter.GenericFilterBean
import org.springframework.web.util.UrlPathHelper
import punkhomov.spring.replaceuser.core.AuthorityChanger
import punkhomov.spring.replaceuser.core.ReplaceUserConstants
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class ReplaceUserFilter(config: Config) : GenericFilterBean() {
    private val authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *> =
        WebAuthenticationDetailsSource()

    private val usernameParameter: String = config.usernameParameter
    private val replaceUserMatcher: RequestMatcher = config.matcher()
    private val refererAttributeName: String? = config.refererAttributeName

    private val successHandler: AuthenticationSuccessHandler = config.successHandler()
    private val failureHandler: AuthenticationFailureHandler = config.failureHandler()

    private val userDetailsService: UserDetailsService = config.userDetailsService()
    private val userDetailsChecker: UserDetailsChecker = config.userDetailsChecker

    private val anonymousKey: String = config.anonymousKey
    private val anonymousPrincipal: Any = config.anonymousPrincipal
    private val anonymousAuthorities: Collection<GrantedAuthority> = config.anonymousAuthorities

    private val authorityChanger: AuthorityChanger? = config.authorityChanger


    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
        doFilter(request as HttpServletRequest, response as HttpServletResponse, chain)
    }

    private fun doFilter(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        // check for replace or exit request
        if (requiresReplaceUser(request)) {
            // if set, attempt replace
            try {
                val targetUser: Authentication = attemptReplaceUser(request)
                // update the current context to the new target user
                SecurityContextHolder.getContext().authentication = targetUser

                // save referer url to session attribute for redirect to previous page
                // by custom AuthenticationSuccessHandler
                saveRefererUrlToSession(request)

                // redirect to target url
                successHandler.onAuthenticationSuccess(request, response, targetUser)
            } catch (ex: AuthenticationException) {
                logger.debug("Failed to replace user", ex)
                failureHandler.onAuthenticationFailure(request, response, ex)
            }
            return
        }
        chain.doFilter(request, response)
    }

    private fun requiresReplaceUser(request: HttpServletRequest): Boolean {
        return replaceUserMatcher.matches(request)
    }

    @Throws(AuthenticationException::class)
    private fun attemptReplaceUser(request: HttpServletRequest): Authentication {
        val username = request.getParameter(usernameParameter) ?: ""

        val targetUserToken = if (username.isNotBlank()) {
            logger.debug(LogMessage.format("Attempt to replace to user [[%s]]", username))
            val targetUser = userDetailsService.loadUserByUsername(username)
            userDetailsChecker.check(targetUser)
            createUsernamePasswordToken(request, targetUser)
        } else {
            logger.debug("Attempt to replace to anonymous user")
            createAnonymousToken(request)
        }
        logger.debug(LogMessage.format("Replace User Token [%s]", targetUserToken))

        return targetUserToken
    }

    private fun createUsernamePasswordToken(
        request: HttpServletRequest,
        targetUser: UserDetails
    ): UsernamePasswordAuthenticationToken {
        var authorities = targetUser.authorities
        if (authorityChanger != null) {
            authorities = authorityChanger.modifyGrantedAuthorities(targetUser, authorities)
        }

        val targetUserToken = UsernamePasswordAuthenticationToken(targetUser, null, authorities)
        targetUserToken.details = authenticationDetailsSource.buildDetails(request)
        return targetUserToken
    }

    private fun createAnonymousToken(request: HttpServletRequest): AnonymousAuthenticationToken {
        var authorities = anonymousAuthorities
        if (authorityChanger != null) {
            authorities = authorityChanger.modifyGrantedAuthorities(null, authorities)
        }

        val anonymousToken = AnonymousAuthenticationToken(anonymousKey, anonymousPrincipal, authorities)
        anonymousToken.details = authenticationDetailsSource.buildDetails(request)
        return anonymousToken
    }

    private fun saveRefererUrlToSession(request: HttpServletRequest) {
        if (refererAttributeName != null) {
            val session = request.getSession(false)
            val refererUrl = request.getHeader("referer")
            if (session != null && refererUrl != null) {
                session.setAttribute(refererAttributeName, refererUrl)
                if (logger.isTraceEnabled) {
                    logger.trace(LogMessage.format("Saving referer url [%s] to current session", refererUrl))
                }
            }
        }
    }

    class Config {
        var replaceUrl: String? = null
        var httpMethod: HttpMethod = ReplaceUserConstants.DEFAULT_HTTP_METHOD
        var usernameParameter: String = ReplaceUserConstants.DEFAULT_USERNAME_PARAMETER
        var refererAttributeName: String? = null

        var successUrl: String? = null
        var failureUrl: String? = null
        var successHandler: AuthenticationSuccessHandler? = null
        var failureHandler: AuthenticationFailureHandler? = null

        var userDetailsService: UserDetailsService? = null
        var userDetailsChecker: UserDetailsChecker = AccountStatusUserDetailsChecker()

        var anonymousKey: String = ReplaceUserConstants.DEFAULT_ANONYMOUS_KEY
        var anonymousPrincipal: Any = ReplaceUserConstants.DEFAULT_ANONYMOUS_PRINCIPAL
        var anonymousAuthorities: Collection<GrantedAuthority> = ReplaceUserConstants.DEFAULT_ANONYMOUS_AUTHORITIES

        var authorityChanger: AuthorityChanger? = null


        internal fun matcher(): AntPathRequestMatcher {
            Assert.notNull(replaceUrl, "replaceUrl must be specified")
            return AntPathRequestMatcher(replaceUrl, httpMethod.name, true, UrlPathHelper())
        }

        internal fun successHandler(): AuthenticationSuccessHandler {
            Assert.isTrue(
                successHandler != null || successUrl != null,
                "You must set either a successHandler or the successUrl"
            )
            return if (successUrl != null) {
                Assert.isNull(successHandler, "You cannot set both successHandler and failureUrl")
                SimpleUrlAuthenticationSuccessHandler(successUrl)
            } else {
                successHandler!!
            }
        }

        internal fun failureHandler(): AuthenticationFailureHandler {
            return if (failureHandler == null) {
                if (failureUrl != null)
                    SimpleUrlAuthenticationFailureHandler(failureUrl)
                else
                    SimpleUrlAuthenticationFailureHandler()
            } else {
                Assert.isNull(failureUrl, "You cannot set both a failureUrl and a failureHandler")
                failureHandler!!
            }
        }

        internal fun userDetailsService(): UserDetailsService {
            Assert.notNull(userDetailsService, "userDetailsService must be specified")
            return userDetailsService!!
        }
    }
}