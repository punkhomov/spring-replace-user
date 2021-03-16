package punkhomov.spring.replaceuser

import org.apache.commons.logging.LogFactory
import org.springframework.core.log.LogMessage
import org.springframework.security.core.Authentication
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import punkhomov.spring.replaceuser.core.ReplaceUserConstants.REDIRECT_LOCATION_ATTRIBUTE_KEY
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ReplaceRedirectBackAuthenticationSuccessHandler(
    private val defaultLocation: String = "/",
    private val redirectStrategy: RedirectStrategy = DefaultRedirectStrategy()
) : AuthenticationSuccessHandler {
    private val logger = LogFactory.getLog(this.javaClass)

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication
    ) {
        val redirectUrl = getRedirectUri(request, response)

        if (response.isCommitted) {
            logger.debug(LogMessage.format("Did not redirect to %s since response already committed.", redirectUrl))
        } else {
            redirectStrategy.sendRedirect(request, response, redirectUrl)
        }
    }

    private fun getRedirectUri(request: HttpServletRequest, response: HttpServletResponse): String {
        return request.session.getAttribute(REDIRECT_LOCATION_ATTRIBUTE_KEY) as? String ?: defaultLocation
    }

//    private fun clearAuthenticationAttributes(request: HttpServletRequest) {
//        val session = request.getSession(false)
//        session?.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)
//    }
}