package eu.wohlben.qits.idp.api;

import eu.wohlben.qits.idp.control.ClientRegistry;
import eu.wohlben.qits.idp.control.IdpClient;
import eu.wohlben.qits.idp.error.OAuthException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * "Who is calling", for the machine surfaces: the commission API, session introspection, and
 * register-token minting.
 *
 * <p><b>One implementation, because it is one credential.</b> A caller here is a platform service
 * that already holds its own idp client id and secret — that is how it gets tokens at all — so
 * checking that pair directly adds nothing to configure: no new audience, no bearer-validation
 * stack inside the service that issues the bearers, no second credential to distribute. It is the
 * same {@code client_secret_basic} the token endpoint accepts, read by the same {@link
 * BasicCredentials} parser and checked by the same {@link ClientRegistry}. This class exists so
 * that stays true as the number of machine surfaces grows.
 *
 * <p><b>And the static-client rule travels with it.</b> A commissioned credential authenticates
 * here — it has to, so a context can hand its own credential back — but it may not commission
 * another, and it may not mint a register token either. Both are the same argument: a credential
 * handed to a build step or an agent container must not be able to produce more access, so the
 * blast radius of a leaked one stops at its own context.
 */
@ApplicationScoped
public class BasicCaller {

  @Inject ClientRegistry registry;

  /**
   * The authenticated caller. Basic only — these are JSON APIs, not the token endpoint, so there is
   * no form to carry credentials and no second place to look.
   *
   * @throws OAuthException {@code invalid_client} (401)
   */
  public IdpClient authenticated(String authorization) {
    BasicCredentials credentials = BasicCredentials.parse(authorization);
    if (credentials == null) {
      throw OAuthException.invalidClient("client authentication is required");
    }
    return registry.authenticate(credentials.clientId(), credentials.secret());
  }

  /**
   * The authenticated caller, refused unless it is a configured <b>service</b> client.
   *
   * @param refusal what the commissioned caller is told it may not do
   * @throws OAuthException {@code invalid_client} (401) when authentication failed, {@code
   *     access_denied} (403) when it succeeded and the caller is a commissioned credential
   */
  public IdpClient staticOnly(String authorization, String refusal) {
    IdpClient caller = authenticated(authorization);
    if (!registry.isStatic(caller.clientId())) {
      throw OAuthException.accessDenied(refusal);
    }
    return caller;
  }
}
