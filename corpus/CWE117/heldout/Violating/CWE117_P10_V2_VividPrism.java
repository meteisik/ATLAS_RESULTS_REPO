import java.util.logging.Logger;

public class CWE117_P10_V2_VividPrism {

    public static String data;

    public void handleVividPrism() {
        if (true) {
            data = System.getenv("VIVID_PRISM_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_VividPrismSink()).logVividPrism();
    }
}

class CWE117_P10_V2_VividPrismSink {
    public void logVividPrism() {
        String data = CWE117_P10_V2_VividPrism.data;
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + data);
    }
}
