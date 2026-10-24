import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticNebula {

    public static String data;

    public void handleArcticNebula() {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ARCTIC_NEBULA_USER");
        }
        (new CWE117_P10_V2_ArcticNebulaSink()).logArcticNebula();
    }
}

class CWE117_P10_V2_ArcticNebulaSink {
    public void logArcticNebula() {
        String data = CWE117_P10_V2_ArcticNebula.data;
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + data);
    }
}
