import java.util.logging.Logger;

public class CWE117_P12_V1_AmberMantisSafe {

    public void handleAmberMantis() {
        String data;
        data = System.getenv("AMBER_MANTIS_USER");
        CWE117_P12_V1_AmberMantisSafeBase baseObject = new CWE117_P12_V1_AmberMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberMantisSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberMantisSafeSink extends CWE117_P12_V1_AmberMantisSafeBase {
    public void action(String data) {
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
