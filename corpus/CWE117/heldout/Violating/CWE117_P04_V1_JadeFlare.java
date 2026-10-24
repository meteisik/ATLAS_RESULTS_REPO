import java.util.logging.Logger;

public class CWE117_P04_V1_JadeFlare {

    private String readJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_USER");
        return data;
    }

    public void handleJadeFlare() {
        String data = readJadeFlare();
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + data);
    }
}
