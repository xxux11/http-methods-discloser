package se.nelmico.httpmethodsdiscloser;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender {
    public static final String ALLOW = "Allow:";
    public static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods:";
    public static final String COMMA_DELIMITER = ",";
    public static final String YELLOW = "yellow";
    public static final String SEPARATOR = " - ";
    public static final String TRACE = "TRACE";
    public static final String HEAD = "HEAD";
    final static String OPTIONS = "OPTIONS";
    final static List<String> EXCLUDE_EXTENSIONS = List.of(".png", ".jpg", ".gif", ".js", ".tif", ".ico", ".css", ".ttf", ".wof");
    public static final String PERIOD = ".";
    final Charset charset = StandardCharsets.UTF_8;
    IBurpExtenderCallbacks callbacks;

    public BurpExtender() {
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        callbacks.registerProxyListener(new IProxyListener() {
            @Override
            public void processProxyMessage(boolean messageIsRequest,
                                            IInterceptedProxyMessage message) {

                if (!messageIsRequest) {
                    return;
                }

                IExtensionHelpers helpers = callbacks.getHelpers();

                IHttpRequestResponse messageInfo = message.getMessageInfo();

                IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                URL url = iRequestInfo.getUrl();

                if (!callbacks.isInScope(url)) {
                    return;
                }

                if (url.toExternalForm().contains(PERIOD)) {
                    String extension = url.toExternalForm().substring(url.toExternalForm().lastIndexOf(PERIOD)).toLowerCase().trim();
                    boolean excludeExtension = EXCLUDE_EXTENSIONS.stream()
                            .anyMatch(ext -> extension.startsWith(ext.toLowerCase().trim()));

                    if (excludeExtension) {
                        return;
                    }
                }

                String req = new String(messageInfo.getRequest(), charset);

                String[] requestSplit = req.split(" ");
                String originalHttpMethod = requestSplit[0];
                requestSplit[0] = OPTIONS;

                IHttpRequestResponse iHttpRequestResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(),
                        StringUtils.join(requestSplit, " ").getBytes());

                IResponseInfo iResponseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());

                List<String> headers = iResponseInfo.getHeaders();

                String allow = headers.stream()
                        .filter(extractAllowMethodsHeader())
                        .map(splitAllowMethodsValue())
                        .collect(Collectors.joining(COMMA_DELIMITER));


                if (allow.isBlank() || allow.isEmpty()) {
                    return;
                }

                List<String> otherHttpMethodsAvailable = Arrays.stream(allow.split(COMMA_DELIMITER))
                        .distinct()
                        .map(String::trim)
                        .filter(Predicate.not(ignoreUnusefulMethods(originalHttpMethod)))
                        .collect(Collectors.toList());

                if (otherHttpMethodsAvailable.size() > 0) {
                    messageInfo.setComment(StringUtils.join(otherHttpMethodsAvailable, SEPARATOR));
                    messageInfo.setHighlight(YELLOW);
                }
            }

            private Predicate<String> extractAllowMethodsHeader() {
                return header -> header.startsWith(ALLOW) || header.startsWith(ACCESS_CONTROL_ALLOW_METHODS);
            }

            private Predicate<String> ignoreUnusefulMethods(final String originalHttpMethod) {
                return method -> List.of(TRACE, OPTIONS, HEAD, originalHttpMethod)
                        .stream()
                        .anyMatch(method::equals);
            }

            private Function<String, String> splitAllowMethodsValue() {
                return allowRow -> allowRow.split(":")[1];
            }

        });
    }

}
