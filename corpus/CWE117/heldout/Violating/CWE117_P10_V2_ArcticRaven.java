import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticRaven {

    public static String data;

    public void handleArcticRaven() {
        if (5 == 5) {
            data = System.getenv("ARCTIC_RAVEN_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticRavenSink()).logArcticRaven();
    }
}

class CWE117_P10_V2_ArcticRavenSink {
    public void logArcticRaven() {
        String data = CWE117_P10_V2_ArcticRaven.data;
        Logger arcticRavenLogger = Logger.getLogger("arcticRaven.audit");
        arcticRavenLogger.info("Login attempt for user " + data);
    }
}
