import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticRaven {

    public void handleArcticRaven() {
        String data;
        data = System.getenv("ARCTIC_RAVEN_USER");
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + data);
    }
}
