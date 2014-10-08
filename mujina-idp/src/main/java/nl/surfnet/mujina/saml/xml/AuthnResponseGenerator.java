/*
 * Copyright 2012 SURFnet bv, The Netherlands
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.surfnet.mujina.saml.xml;

import nl.surfnet.mujina.model.IdpConfiguration;
import nl.surfnet.mujina.model.SimpleAuthentication;
import nl.surfnet.mujina.util.IDService;
import nl.surfnet.mujina.util.TimeService;

import org.joda.time.DateTime;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.security.core.AuthenticationException;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

public class AuthnResponseGenerator {

  private final XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();

  private final IssuerGenerator issuerGenerator;
  private final AssertionGenerator assertionGenerator;
  private final IDService idService;
  private final TimeService timeService;
  private final IdpConfiguration idpConfiguration;
  private final Credential signingCredential;

  StatusGenerator statusGenerator;

  public AuthnResponseGenerator(final Credential signingCredential, String issuingEntityName, TimeService timeService, IDService idService,
      IdpConfiguration idpConfiguration) {
    super();
    this.idService = idService;
    this.timeService = timeService;
    issuerGenerator = new IssuerGenerator(issuingEntityName);
    this.idpConfiguration = idpConfiguration;
    this.signingCredential = signingCredential;
    assertionGenerator = new AssertionGenerator(signingCredential, issuingEntityName, timeService, idService, idpConfiguration);
    statusGenerator = new StatusGenerator();
  }

  public Response generateAuthnResponse(String remoteIP, SimpleAuthentication authToken, String recepientAssertionConsumerURL,
      int validForInSeconds, String inResponseTo, DateTime authnInstant, String attributeJson, String requestingEntityId) {

    ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
    Response authResponse = responseBuilder.buildObject();

    Issuer responseIssuer = issuerGenerator.generateIssuer();

    Assertion assertion = assertionGenerator.generateAssertion(remoteIP, authToken, recepientAssertionConsumerURL, validForInSeconds,
        inResponseTo, authnInstant, attributeJson, requestingEntityId);

    authResponse.setIssuer(responseIssuer);
    authResponse.setID(idService.generateID());
    authResponse.setIssueInstant(timeService.getCurrentDateTime());
    authResponse.setInResponseTo(inResponseTo);
    authResponse.getAssertions().add(assertion);
    authResponse.setDestination(recepientAssertionConsumerURL);
    authResponse.setStatus(statusGenerator.generateStatus(StatusCode.SUCCESS_URI));

    if (idpConfiguration.needsSignResponse()) {
      signResponse(authResponse);
    }

    return authResponse;
  }

  //TODO refactor
  private void signResponse(final SignableSAMLObject response) {
      Signature signature = (Signature) org.opensaml.Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
              .buildObject(Signature.DEFAULT_ELEMENT_NAME);
      signature.setSigningCredential(signingCredential);
      signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
      signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
      response.setSignature(signature);
      try {
          org.opensaml.Configuration.getMarshallerFactory().getMarshaller(response).marshall(response);
      } catch (MarshallingException e) {
          e.printStackTrace();
      }
      try {
          Signer.signObject(signature);
      } catch (SignatureException e) {
          e.printStackTrace();
      }
  }

  public Response generateAuthnResponseFailure(String recepientAssertionConsumerURL, String inResponseTo, AuthenticationException ae) {

    ResponseBuilder responseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
    Response authResponse = responseBuilder.buildObject();

    Issuer responseIssuer = issuerGenerator.generateIssuer();

    authResponse.setIssuer(responseIssuer);
    authResponse.setID(idService.generateID());
    authResponse.setIssueInstant(timeService.getCurrentDateTime());
    authResponse.setInResponseTo(inResponseTo);
    authResponse.setDestination(recepientAssertionConsumerURL);
    authResponse.setStatus(statusGenerator.generateStatus(StatusCode.RESPONDER_URI, StatusCode.AUTHN_FAILED_URI, ae.getClass().getName()));

    return authResponse;

  }

}
