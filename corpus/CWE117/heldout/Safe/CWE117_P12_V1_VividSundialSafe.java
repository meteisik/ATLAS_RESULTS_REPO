import java.util.logging.Logger;

public class CWE117_P12_V1_VividSundialSafe {

    public void handleVividSundial() {
        String data;
        data = System.getenv("VIVID_SUNDIAL_USER");
        CWE117_P12_V1_VividSundialSafeBase baseObject = new CWE117_P12_V1_VividSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividSundialSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividSundialSafeSink extends CWE117_P12_V1_VividSundialSafeBase {
    public void action(String data) {
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
