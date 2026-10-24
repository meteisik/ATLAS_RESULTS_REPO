import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticNebulaSafe {
    private static boolean privateTrue = true;

    public void handleArcticNebula() {
        String data;
        if (privateTrue) {
            data = System.getenv("ARCTIC_NEBULA_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticNebulaSafeBase baseObject = new CWE117_P12_V2_ArcticNebulaSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticNebulaSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticNebulaSafeSink extends CWE117_P12_V2_ArcticNebulaSafeBase {
    public void action(String data) {
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
