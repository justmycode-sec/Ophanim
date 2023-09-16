package oculos;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.CollaboratorServer;
import burp.api.montoya.collaborator.DnsQueryType;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.collaborator.InteractionId;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.collaborator.PayloadOption;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.SmtpProtocol;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.core.Version;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
//import burp.api.montoya.http.ContentType;
import burp.api.montoya.http.Http;
//import burp.api.montoya.http.HttpHandler;
import burp.api.montoya.http.HttpProtocol;
import burp.api.montoya.http.HttpService;
//import burp.api.montoya.http.HttpTransformation;
//import burp.api.montoya.http.RequestResult;
//import burp.api.montoya.http.ResponseResult;
import burp.api.montoya.http.message.HttpRequestResponse;
//import burp.api.montoya.http.message.MarkedHttpRequestResponse;
//import burp.api.montoya.http.message.cookies.Cookie;
//import burp.api.montoya.http.message.headers.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.intruder.Intruder;
import burp.api.montoya.intruder.IntruderInsertionPoint;
//import burp.api.montoya.intruder.Payload;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.persistence.Preferences;
//import burp.api.montoya.proxy.InterceptedHttpRequest;
//import burp.api.montoya.proxy.InterceptedHttpResponse;
import burp.api.montoya.proxy.Proxy;
//import burp.api.montoya.proxy.ProxyHttpRequestHandler;
//import burp.api.montoya.proxy.ProxyHttpResponseHandler;
//import burp.api.montoya.proxy.ProxyRequestResponse;
//import burp.api.montoya.proxy.RequestFinalInterceptResult;
//import burp.api.montoya.proxy.RequestInitialInterceptResult;
//import burp.api.montoya.proxy.ResponseFinalInterceptResult;
//import burp.api.montoya.proxy.ResponseInitialInterceptResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.Crawl;
//import burp.api.montoya.scanner.InvalidLauncherConfigurationException;
//import burp.api.montoya.scanner.Scan;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
//import burp.api.montoya.scanner.audit.insertionpoint.ExtensionGeneratedAuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.scope.ScopeChange;
import burp.api.montoya.scope.ScopeChangeHandler;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
//import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditor;
//import burp.api.montoya.ui.editor.extension.ExtensionHttpRequestEditorProvider;
//import burp.api.montoya.ui.editor.extension.ExtensionHttpResponseEditor;
//import burp.api.montoya.ui.editor.extension.ExtensionHttpResponseEditorProvider;
import burp.api.montoya.utilities.Utilities;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.WebSocket;
//import burp.api.montoya.websocket.WebSocketBinaryMessage;
//import burp.api.montoya.websocket.WebSocketCreationHandler;
//import burp.api.montoya.websocket.WebSocketHandler;
//import burp.api.montoya.websocket.WebSocketTextMessage;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static burp.api.montoya.core.Annotations.annotations;
import static burp.api.montoya.core.ByteArray.byteArray;
import static burp.api.montoya.core.Range.range;
import static burp.api.montoya.http.HttpMode.HTTP_1;
import static burp.api.montoya.http.HttpMode.HTTP_2;
import static burp.api.montoya.http.HttpMode.HTTP_2_IGNORE_ALPN;
import static burp.api.montoya.http.HttpService.httpService;
//import static burp.api.montoya.http.RequestResult.requestResult;
//import static burp.api.montoya.http.ResponseResult.responseResult;
//import static burp.api.montoya.http.message.MarkedHttpRequestResponse.markedRequestResponse;
//import static burp.api.montoya.http.message.headers.HttpHeader.httpHeader;
import static burp.api.montoya.http.message.params.HttpParameter.bodyParameter;
import static burp.api.montoya.http.message.params.HttpParameter.cookieParameter;
import static burp.api.montoya.http.message.params.HttpParameter.urlParameter;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequest;
import static burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl;
//import static burp.api.montoya.http.message.requests.HttpRequest.httpVerbatimRequest;
import static burp.api.montoya.http.message.responses.HttpResponse.httpResponse;
//import static burp.api.montoya.scanner.BuiltInScanConfiguration.ACTIVE_AUDIT_CHECKS;
//import static burp.api.montoya.scanner.BuiltInScanConfiguration.PASSIVE_AUDIT_CHECKS;
import static burp.api.montoya.scanner.ReportFormat.XML;
import static burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint.auditInsertionPoint;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static burp.api.montoya.ui.Selection.selection;
//import static burp.api.montoya.websocket.WebSocketBinaryMessage.continueWithBinaryMessage;
//import static burp.api.montoya.websocket.WebSocketTextMessage.continueWithTextMessage;
//import static burp.api.montoya.websocket.WebSocketTextMessage.dropTextMessage;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.emptyList;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.core.JsonProcessingException;

public abstract class Oculus {

    public boolean isInit;
    public OculusConfig config;

    public Oculus(){
        config = new OculusConfig() {
            @Override
            public boolean checkConfig() {
                return super.checkConfig();
            }
        };
    }

    public String init(String configJSON){
        ObjectMapper objectMapper = new ObjectMapper();
        try{
            config = objectMapper.readValue(configJSON, config.getClass());
            isInit = true;
        }catch(Exception e){
            isInit = false;
        }
        return "Abstract Method not Implemented!";
    };

    public boolean isValidRequestForOculus(HttpRequest packedRequest){
        return true;
    }

    public String getConfigAsJSON(){
        String json;
        //return "blah";
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        try{
            json = ow.writeValueAsString(config);
        }catch(JsonProcessingException e){
            json = "{\"Error\":\"" + e.getMessage() + "\"}";
        }
        return json;
    }

    private HttpRequest doPrePack(HttpRequest unpackedRequest){
        return unpackedRequest;
    }

    abstract HttpRequest doPackRequest(HttpRequest unpackedRequest);

    public HttpRequest packRequest(HttpRequest unpackedRequest){
        unpackedRequest = doPrePack(unpackedRequest);
        HttpRequest packedRequest = doPackRequest(unpackedRequest);
        return doPostPack(packedRequest);
    };

    private HttpRequest doPostPack(HttpRequest packedRequest){
        return packedRequest;
    }

    private HttpRequest doPreUnpack(HttpRequest packedRequest){
        return packedRequest;
    }

    abstract HttpRequest doUnpackRequest(HttpRequest packedRequest);

    public HttpRequest unpackRequest(HttpRequest packedRequest){
        packedRequest = doPreUnpack(packedRequest);
        HttpRequest unpackedRequest = doUnpackRequest(packedRequest);
        return doPostUnpack(unpackedRequest);
    };

    private HttpRequest doPostUnpack(HttpRequest unpackedRequest){
        return unpackedRequest;
    }

}
