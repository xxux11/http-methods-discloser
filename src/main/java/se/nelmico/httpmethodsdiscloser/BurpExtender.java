package se.nelmico.httpmethodsdiscloser;

import burp.*;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender {
    public static final String NO_ALLOW_HEADER_AVAILABLE = "NO_ALLOW_HEADER_AVAILABLE";
    final static String OPTIONS = "OPTIONS";
    final static List<String> EXCLUDE_EXTENSIONS = List.of(".png", ".jpg", ".gif", ".js", ".tif", ".ico", ".css");
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
                String req = new String(messageInfo.getRequest(), charset);

                IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
                String url = iRequestInfo.getUrl().toExternalForm();

                if (url.contains(".")) {
                    String extension = url.substring(url.lastIndexOf(".")).toLowerCase().trim();
                    boolean excludeExtension = EXCLUDE_EXTENSIONS.stream()
                            .anyMatch(ext -> extension.startsWith(ext.toLowerCase().trim()));

                    if (excludeExtension) {
                        return;
                    }
                }

                String[] requestSplit = req.split(" ");
                String originalHttpMethod = requestSplit[0];
                requestSplit[0] = OPTIONS;
                IHttpRequestResponse iHttpRequestResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(),
                        StringUtils.join(requestSplit, " ").getBytes());
                IResponseInfo iResponseInfo = helpers.analyzeResponse(iHttpRequestResponse.getResponse());

                List<String> headers = iResponseInfo.getHeaders();
                String allow = headers.stream()
                        .filter(s1 -> s1.startsWith("Allow:"))
                        .findFirst()
                        .orElse(NO_ALLOW_HEADER_AVAILABLE);

                if (allow.equals(NO_ALLOW_HEADER_AVAILABLE)) {
                    return;
                }

                String allowValues = allow.split(":")[1].trim();

                if (allowValues.length() == 0) {
                    return;
                }

                List<String> otherHttpMethodsAvailable = Arrays.stream(allowValues.split(","))
                        .filter(s -> !s.contains("HEAD"))
                        .filter(s -> !s.contains("OPTIONS"))
                        .filter(s -> !s.contains("TRACE"))
                        .filter(s -> !s.contains(originalHttpMethod))
                        .map(String::trim)
                        .collect(Collectors.toList());

                if (otherHttpMethodsAvailable.size() > 0) {
                    messageInfo.setComment(StringUtils.join(otherHttpMethodsAvailable, " - "));
                    messageInfo.setHighlight("yellow");
                }
            }
        });
    }
}
