import java.util.logging.Logger;

public class CWE117_P12_V1_AmberQuartzSafe {

    public void handleAmberQuartz() {
        String data;
        data = System.getenv("AMBER_QUARTZ_USER");
        CWE117_P12_V1_AmberQuartzSafeBase baseObject = new CWE117_P12_V1_AmberQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberQuartzSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberQuartzSafeSink extends CWE117_P12_V1_AmberQuartzSafeBase {
    public void action(String data) {
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
