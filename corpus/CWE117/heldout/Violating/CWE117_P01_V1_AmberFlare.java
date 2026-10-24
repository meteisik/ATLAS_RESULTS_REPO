import java.util.logging.Logger;

public class CWE117_P01_V1_AmberFlare {

    public void handleAmberFlare() {
        String data;
        data = System.getenv("AMBER_FLARE_USER");
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + data);
    }
}
