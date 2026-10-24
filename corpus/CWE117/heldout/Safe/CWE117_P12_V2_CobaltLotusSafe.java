import java.util.logging.Logger;

public class CWE117_P12_V2_CobaltLotusSafe {
    private static boolean privateTrue = true;

    public void handleCobaltLotus() {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_LOTUS_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CobaltLotusSafeBase baseObject = new CWE117_P12_V2_CobaltLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CobaltLotusSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CobaltLotusSafeSink extends CWE117_P12_V2_CobaltLotusSafeBase {
    public void action(String data) {
        Logger cobaltLotusLogger = Logger.getLogger("cobaltLotus.audit");
        cobaltLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
