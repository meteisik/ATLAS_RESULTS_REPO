import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticKestrel {

    public void handleArcticKestrel() {
        String data;
        data = System.getenv("ARCTIC_KESTREL_USER");
        Logger arcticKestrelLogger = Logger.getLogger("arcticKestrel.audit");
        arcticKestrelLogger.info("Login attempt for user " + data);
    }
}
