import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonNebulaSafe {

    public void handleCrimsonNebula() {
        String data;
        while (true) {
            data = System.getenv("CRIMSON_NEBULA_USER");
            break;
        }
        CWE117_P12_V2_CrimsonNebulaSafeBase baseObject = new CWE117_P12_V2_CrimsonNebulaSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonNebulaSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonNebulaSafeSink extends CWE117_P12_V2_CrimsonNebulaSafeBase {
    public void action(String data) {
        Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
        crimsonNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
