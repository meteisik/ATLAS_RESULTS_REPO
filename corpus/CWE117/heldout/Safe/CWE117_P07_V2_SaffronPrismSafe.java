import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronPrismSafe {

    public void handleSaffronPrism() {
        String data;
        while (true) {
            data = (new CWE117_P07_V2_SaffronPrismSafeSource()).readSaffronPrism();
            break;
        }
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronPrismSafeSource {
    public String readSaffronPrism() {
        String data;
        data = System.getenv("SAFFRON_PRISM_USER");
        return data;
    }
}
