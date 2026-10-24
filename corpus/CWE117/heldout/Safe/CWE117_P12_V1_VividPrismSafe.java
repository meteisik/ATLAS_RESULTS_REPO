import java.util.logging.Logger;

public class CWE117_P12_V1_VividPrismSafe {

    public void handleVividPrism() {
        String data;
        data = System.getenv("VIVID_PRISM_USER");
        CWE117_P12_V1_VividPrismSafeBase baseObject = new CWE117_P12_V1_VividPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividPrismSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividPrismSafeSink extends CWE117_P12_V1_VividPrismSafeBase {
    public void action(String data) {
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
