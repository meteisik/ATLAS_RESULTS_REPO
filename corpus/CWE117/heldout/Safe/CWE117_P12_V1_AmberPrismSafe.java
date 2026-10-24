import java.util.logging.Logger;

public class CWE117_P12_V1_AmberPrismSafe {

    public void handleAmberPrism() {
        String data;
        data = System.getenv("AMBER_PRISM_USER");
        CWE117_P12_V1_AmberPrismSafeBase baseObject = new CWE117_P12_V1_AmberPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberPrismSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberPrismSafeSink extends CWE117_P12_V1_AmberPrismSafeBase {
    public void action(String data) {
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
