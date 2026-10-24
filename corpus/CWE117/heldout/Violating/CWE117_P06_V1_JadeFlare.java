import java.util.logging.Logger;

public class CWE117_P06_V1_JadeFlare {

    public void handleJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_USER");
        (new CWE117_P06_V1_JadeFlareSink()).logJadeFlare(data);
    }
}

class CWE117_P06_V1_JadeFlareSink {
    public void logJadeFlare(String data) {
        Logger jadeFlareLogger = Logger.getLogger("jadeFlare.audit");
        jadeFlareLogger.info("Login attempt for user " + data);
    }
}
