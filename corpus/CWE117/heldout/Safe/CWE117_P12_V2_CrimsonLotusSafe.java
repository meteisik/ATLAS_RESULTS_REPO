import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonLotusSafe {

    public void handleCrimsonLotus() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("CRIMSON_LOTUS_USER");
            break;
        default:
            data = null;
            break;
        }
        CWE117_P12_V2_CrimsonLotusSafeBase baseObject = new CWE117_P12_V2_CrimsonLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonLotusSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonLotusSafeSink extends CWE117_P12_V2_CrimsonLotusSafeBase {
    public void action(String data) {
        Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
        crimsonLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
