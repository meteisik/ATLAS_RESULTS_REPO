import java.util.logging.Logger;

public class CWE117_P05_V1_JadeFlare {

    private String jadeFlareData;

    private void logJadeFlare() {
        String data = jadeFlareData;
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + data);
    }

    public void handleJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_USER");
        jadeFlareData = data;
        logJadeFlare();
    }
}
