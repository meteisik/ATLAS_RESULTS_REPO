import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronPrism {

    public static String data;

    public void handleSaffronPrism() {
        data = System.getenv("SAFFRON_PRISM_USER");
        (new CWE117_P10_V1_SaffronPrismSink()).logSaffronPrism();
    }
}

class CWE117_P10_V1_SaffronPrismSink {
    public void logSaffronPrism() {
        String data = CWE117_P10_V1_SaffronPrism.data;
        Logger saffronPrismLogger = Logger.getLogger("saffronPrism.audit");
        saffronPrismLogger.info("Login attempt for user " + data);
    }
}
