package punkhomov.spring.replaceuser

import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.core.log.LogMessage
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsChecker
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers
import org.springframework.util.Assert
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import org.springframework.web.server.WebSession
import punkhomov.spring.replaceuser.core.AuthorityChanger
import punkhomov.spring.replaceuser.core.ReplaceUserConstants
import reactor.core.publisher.Mono
import reactor.kotlin.core.publisher.switchIfEmpty

class ReplaceUserWebFilter(config: Config) : WebFilter {
    private val logger: Log = LogFactory.getLog(javaClass)

    private val securityContextRepository: ServerSecurityContextRepository =
        WebSessionServerSecurityContextRepository()

    private val usernameParameter: String = config.usernameParameter
    private val replaceUserMatcher: ServerWebExchangeMatcher = config.matcher()
    private val refererAttributeName: String? = config.refererAttributeName

    private val successHandler: ServerAuthenticationSuccessHandler = config.successHandler()
    private val failureHandler: ServerAuthenticationFailureHandler? = config.failureHandler()

    private val userDetailsService: ReactiveUserDetailsService = config.userDetailsService()
    private val userDetailsChecker: UserDetailsChecker = config.userDetailsChecker

    private val anonymousKey: String = config.anonymousKey
    private val anonymousPrincipal: Any = config.anonymousPrincipal
    private val anonymousAuthorities: Collection<GrantedAuthority> = config.anonymousAuthorities

    private val authorityChanger: AuthorityChanger? = config.authorityChanger


    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val webFilterExchange = WebFilterExchange(exchange, chain)
        return replaceUser(webFilterExchange)
            .switchIfEmpty { chain.filter(exchange).then(Mono.empty()) }
            .doOnNextAsMonoVoid { saveReferer(exchange) }
            .flatMap { auth -> onAuthenticationSuccess(auth, webFilterExchange) }
            .onErrorResume(ReplaceUserAuthenticationException::class.java) { Mono.empty() }
    }

    private fun replaceUser(webFilterExchange: WebFilterExchange): Mono<Authentication> {
        return replaceUserMatcher.matches(webFilterExchange.exchange)
            .doOnNext {
                val match = it.isMatch
                logger.debug(match)
            }
            .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
            .flatMap {
                ReactiveSecurityContextHolder.getContext()
            }
            .map {
                it.authentication
            }
//            .map(SecurityContext::getAuthentication)
            .flatMap { authentication ->
                attemptReplaceUser(webFilterExchange.exchange, authentication)
            }.onErrorResume(AuthenticationException::class.java) { ex ->
                onAuthenticationFailure(ex, webFilterExchange)
                    .then(Mono.error(ReplaceUserAuthenticationException(ex)))
            }
    }

    private fun attemptReplaceUser(exchange: ServerWebExchange, currentAuth: Authentication): Mono<Authentication> {
        return retrieveUsername(exchange)
            .flatMap { username ->
                if (username.isNotEmpty()) {
                    logger.debug(LogMessage.format("Attempt to switch to user [%s]", username))
                    userDetailsService.findByUsername(username)
                        .switchIfEmpty(Mono.error(::noTargetAuthenticationException))
                        .doOnNext(userDetailsChecker::check)
                        .map(::createUsernamePasswordToken)
                } else {
                    logger.debug("Attempt to replace to anonymous user")
                    Mono.just(createAnonymousToken())
                }

            }
    }

    private fun createUsernamePasswordToken(targetUser: UserDetails): Authentication {
        var authorities = targetUser.authorities
        if (authorityChanger != null) {
            authorities = authorityChanger.modifyGrantedAuthorities(targetUser, authorities)
        }
        return UsernamePasswordAuthenticationToken(targetUser, null, authorities)
    }

    private fun createAnonymousToken(): Authentication {
        var authorities = anonymousAuthorities
        if (authorityChanger != null) {
            authorities = authorityChanger.modifyGrantedAuthorities(null, authorities)
        }
        return AnonymousAuthenticationToken(anonymousKey, anonymousPrincipal, authorities)
    }

    private fun <T> Mono<T>.doOnNextAsMonoVoid(transformer: (T) -> Mono<Void>): Mono<T> {
        return flatMap {
            transformer.invoke(it).then(Mono.just(it))
        }
    }

    private fun saveReferer(exchange: ServerWebExchange): Mono<Void> {
        val referer = exchange.request.headers.getFirst("referer")
        return if (refererAttributeName != null && referer != null) {
            exchange.session
                .map(WebSession::getAttributes)
                .doOnNext { attrs ->
                    attrs[refererAttributeName] = referer
                    if (logger.isTraceEnabled) {
                        logger.trace(LogMessage.format("Saving referer url [%s] to current session", referer))
                    }
                }
                .then(emptyMono())
        } else {
            emptyMono()
        }

    }

    private fun onAuthenticationSuccess(
        authentication: Authentication,
        webFilterExchange: WebFilterExchange
    ): Mono<Void> {
        logger.debug("onAuthenticationSuccess")
        val exchange = webFilterExchange.exchange
        val securityContext = SecurityContextImpl(authentication)
        return securityContextRepository.save(exchange, securityContext)
            .then(successHandler.onAuthenticationSuccess(webFilterExchange, authentication))
            .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)))
    }

    private fun onAuthenticationFailure(
        exception: AuthenticationException,
        webFilterExchange: WebFilterExchange
    ): Mono<Void> {
        return Mono.justOrEmpty(failureHandler).switchIfEmpty(Mono.defer {
            logger.error("Replace user failed", exception)
            Mono.error(exception)
        }).flatMap { handler -> handler!!.onAuthenticationFailure(webFilterExchange, exception) }
    }

    private fun noTargetAuthenticationException(): AuthenticationCredentialsNotFoundException {
        return AuthenticationCredentialsNotFoundException("No target user for the given username")
    }

    private fun retrieveUsername(exchange: ServerWebExchange): Mono<String> {
        return exchange.formData
            .mapNotNull {
                it.getFirst(usernameParameter)
            }
            .switchIfEmpty {
                val username: String? = exchange.request.queryParams.getFirst(usernameParameter)
                Mono.just(username ?: "")
            }
//            .defaultIfEmpty()
    }

    private fun getUsername(exchange: ServerWebExchange): String? {
        return exchange.request.queryParams.getFirst(usernameParameter)
    }


    class ReplaceUserAuthenticationException(
        exception: AuthenticationException
    ) : RuntimeException(exception)

    class Config {
        var replaceUrl: String? = null
        var httpMethod: HttpMethod = ReplaceUserConstants.DEFAULT_HTTP_METHOD
        var usernameParameter: String = ReplaceUserConstants.DEFAULT_USERNAME_PARAMETER
        var refererAttributeName: String? = null

        var successUrl: String? = null
        var failureUrl: String? = null
        var successHandler: ServerAuthenticationSuccessHandler? = null
        var failureHandler: ServerAuthenticationFailureHandler? = null

        var userDetailsService: ReactiveUserDetailsService? = null
        var userDetailsChecker: UserDetailsChecker = AccountStatusUserDetailsChecker()

        var anonymousKey: String = ReplaceUserConstants.DEFAULT_ANONYMOUS_KEY
        var anonymousPrincipal: Any = ReplaceUserConstants.DEFAULT_ANONYMOUS_PRINCIPAL
        var anonymousAuthorities: Collection<GrantedAuthority> = ReplaceUserConstants.DEFAULT_ANONYMOUS_AUTHORITIES

        var authorityChanger: AuthorityChanger? = null


        internal fun matcher(): ServerWebExchangeMatcher {
            Assert.notNull(replaceUrl, "replaceUrl must be specified")
            return ServerWebExchangeMatchers.pathMatchers(httpMethod, replaceUrl)
        }

        internal fun successHandler(): ServerAuthenticationSuccessHandler {
            return if (successUrl != null) {
                Assert.isNull(successHandler, "You cannot set both a successUrl and a successHandler")
                RedirectServerAuthenticationSuccessHandler(successUrl)
            } else {
                Assert.notNull(successHandler, "You must set either a successUrl or the successHandler")
                successHandler!!
            }
        }

        internal fun failureHandler(): ServerAuthenticationFailureHandler? {
            return if (failureHandler == null) {
                if (failureUrl != null) {
                    RedirectServerAuthenticationFailureHandler(failureUrl)
                } else {
                    null
                }
            } else {
                Assert.isNull(failureUrl, "You cannot set both a failureUrl and a failureHandler")
                failureHandler
            }
        }

        internal fun userDetailsService(): ReactiveUserDetailsService {
            Assert.notNull(userDetailsService, "userDetailsService must be specified")
            return userDetailsService!!
        }
    }
}