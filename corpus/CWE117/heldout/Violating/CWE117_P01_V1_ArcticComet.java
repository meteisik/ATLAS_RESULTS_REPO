import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticComet {

    public void handleArcticComet() {
        String data;
        data = System.getenv("ARCTIC_COMET_USER");
        Logger arcticCometLogger = Logger.getLogger("arcticComet.audit");
        arcticCometLogger.info("Login attempt for user " + data);
    }
}
