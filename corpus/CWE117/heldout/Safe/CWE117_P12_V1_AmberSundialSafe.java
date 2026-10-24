import java.util.logging.Logger;

public class CWE117_P12_V1_AmberSundialSafe {

    public void handleAmberSundial() {
        String data;
        data = System.getenv("AMBER_SUNDIAL_USER");
        CWE117_P12_V1_AmberSundialSafeBase baseObject = new CWE117_P12_V1_AmberSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberSundialSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberSundialSafeSink extends CWE117_P12_V1_AmberSundialSafeBase {
    public void action(String data) {
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
