package burp;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        se.nelmico.httpmethodsdiscloser.BurpExtender extender = new se.nelmico.httpmethodsdiscloser.BurpExtender();
        extender.registerExtenderCallbacks(callbacks);
    }
}
