import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticNebula {

    public void handleArcticNebula() {
        String data;
        data = System.getenv("ARCTIC_NEBULA_USER");
        Logger arcticNebulaLogger = Logger.getLogger("arcticNebula.audit");
        arcticNebulaLogger.info("Login attempt for user " + data);
    }
}
