import java.util.logging.Logger;

public class CWE117_P03_V2_JadeFlare {
    private static boolean privateTrue = true;

    private void logJadeFlare(String data) {
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + data);
    }

    public void handleJadeFlare() {
        String data;
        if (privateTrue) {
            data = System.getenv("JADE_FLARE_USER");
        } else {
            data = null;
        }
        logJadeFlare(data);
    }
}
