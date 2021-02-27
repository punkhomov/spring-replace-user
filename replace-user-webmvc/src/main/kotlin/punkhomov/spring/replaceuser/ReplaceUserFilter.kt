package punkhomov.spring.replaceuser

import org.springframework.core.log.LogMessage
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationDetailsSource
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
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
import punkhomov.spring.replaceuser.core.ReplaceUserFilterConfig
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class ReplaceUserFilter(config: ReplaceUserFilterConfig) : GenericFilterBean() {
    private val authenticationDetailsSource: AuthenticationDetailsSource<HttpServletRequest, *> =
        WebAuthenticationDetailsSource()

    private val usernameParameter: String = config.usernameParameter
    private val replaceUserMatcher: RequestMatcher
    private val refererUrlAttributeName: String? = config.refererUrlAttributeName

    private val successHandler: AuthenticationSuccessHandler
    private val failureHandler: AuthenticationFailureHandler

    private val userDetailsService: UserDetailsService
    private val userDetailsChecker: UserDetailsChecker = config.userDetailsChecker

    private val anonymousKey = config.anonymousKey
    private val anonymousPrincipal = config.anonymousPrincipal
    private val anonymousAuthorities = config.anonymousAuthorities

    private val authorityChanger: AuthorityChanger? = config.authorityChanger

    init {
        Assert.notNull(config.replaceUrl, "replaceUrl must be specified")
        this.replaceUserMatcher =
            AntPathRequestMatcher(config.replaceUrl, config.httpMethod.name, true, UrlPathHelper())

        Assert.notNull(config.userDetailsService, "userDetailsService must be specified")
        this.userDetailsService = config.userDetailsService!!

        Assert.isTrue(
            config.successHandler != null || config.successUrl != null,
            "You must set either a successHandler or the successUrl"
        )
        this.successHandler = if (config.successUrl != null) {
            Assert.isNull(config.successHandler, "You cannot set both successHandler and failureUrl")
            SimpleUrlAuthenticationSuccessHandler(config.successUrl)
        } else {
            config.successHandler!!
        }

        this.failureHandler = if (config.failureHandler == null) {
            if (config.failureUrl != null)
                SimpleUrlAuthenticationFailureHandler(config.failureUrl)
            else
                SimpleUrlAuthenticationFailureHandler()
        } else {
            Assert.isNull(config.failureUrl, "You cannot set both a switchFailureUrl and a failureHandler")
            config.failureHandler!!
        }
    }

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
        if (refererUrlAttributeName != null) {
            val session = request.getSession(false)
            val refererUrl = request.getHeader("referer")
            if (session != null && refererUrl != null) {
                session.setAttribute(refererUrlAttributeName, refererUrl)
                if (logger.isTraceEnabled) {
                    logger.trace(LogMessage.format("Saving referer url [%s] to current session", refererUrl))
                }
            }
        }
    }
}