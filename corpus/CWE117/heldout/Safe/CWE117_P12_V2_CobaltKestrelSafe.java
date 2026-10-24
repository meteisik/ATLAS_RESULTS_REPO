import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltKestrelSafe {

    public void handleCobaltKestrel() {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_KESTREL_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltKestrelSafeBase baseObject = new CWE117_P12_V2_CobaltKestrelSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltKestrelSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltKestrelSafeSink extends CWE117_P12_V2_CobaltKestrelSafeBase {
    public void action(String data) {
        Logger cobaltKestrelLogger = Logger.getLogger("cobaltKestrel.audit");
        cobaltKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
