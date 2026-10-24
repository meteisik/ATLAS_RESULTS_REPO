import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticNebulaSafe {

    public static String data;

    public void handleArcticNebula() {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_NEBULA_USER");
        }
        (new CWE117_P10_V2_ArcticNebulaSafeSink()).logArcticNebula();
    }
}

class CWE117_P10_V2_ArcticNebulaSafeSink {
    public void logArcticNebula() {
        String data = CWE117_P10_V2_ArcticNebulaSafe.data;
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
