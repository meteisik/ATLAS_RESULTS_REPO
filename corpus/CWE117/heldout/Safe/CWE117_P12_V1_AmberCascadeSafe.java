import java.util.logging.Logger;

public class CWE117_P12_V1_AmberCascadeSafe {

    public void handleAmberCascade() {
        String data;
        data = System.getenv("AMBER_CASCADE_USER");
        CWE117_P12_V1_AmberCascadeSafeBase baseObject = new CWE117_P12_V1_AmberCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberCascadeSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberCascadeSafeSink extends CWE117_P12_V1_AmberCascadeSafeBase {
    public void action(String data) {
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
