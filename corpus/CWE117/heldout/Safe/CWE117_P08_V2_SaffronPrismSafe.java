import java.util.logging.Logger;

public class CWE117_P08_V2_SaffronPrismSafe {

    public void handleSaffronPrism() {
        String data;
        if (true) {
            data = System.getenv("SAFFRON_PRISM_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SaffronPrismSafeSink()).logSaffronPrism(dataArray);
    }
}

class CWE117_P08_V2_SaffronPrismSafeSink {
    public void logSaffronPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
