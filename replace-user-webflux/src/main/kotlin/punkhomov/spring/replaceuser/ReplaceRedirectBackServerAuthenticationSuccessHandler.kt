package punkhomov.spring.replaceuser

import org.springframework.security.core.Authentication
import org.springframework.security.web.server.DefaultServerRedirectStrategy
import org.springframework.security.web.server.ServerRedirectStrategy
import org.springframework.security.web.server.WebFilterExchange
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler
import org.springframework.web.server.ServerWebExchange
import punkhomov.spring.replaceuser.core.ReplaceUserConstants.REDIRECT_LOCATION_ATTRIBUTE_KEY
import reactor.core.publisher.Mono
import java.net.URI

class ReplaceRedirectBackServerAuthenticationSuccessHandler(
    defaultLocation: String = "/",
    private val redirectStrategy: ServerRedirectStrategy = DefaultServerRedirectStrategy()
) : ServerAuthenticationSuccessHandler {
    private var defaultUriLocation = URI.create(defaultLocation)

    override fun onAuthenticationSuccess(
        webFilterExchange: WebFilterExchange,
        authentication: Authentication
    ): Mono<Void> {
        val exchange = webFilterExchange.exchange
        return getRedirectUri(exchange).defaultIfEmpty(defaultUriLocation)
            .flatMap { redirectStrategy.sendRedirect(exchange, it) }
    }

    private fun getRedirectUri(exchange: ServerWebExchange): Mono<URI> {
        return exchange.session
            .flatMap { Mono.justOrEmpty(it.getAttribute<String>(REDIRECT_LOCATION_ATTRIBUTE_KEY)) }
            .map(URI::create)
    }
}