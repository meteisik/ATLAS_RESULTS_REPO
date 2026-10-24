import java.util.logging.Logger;

public class CWE117_P10_V2_AmberFlare {

    public static String data;

    public void handleAmberFlare() {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberFlareSink()).logAmberFlare();
    }
}

class CWE117_P10_V2_AmberFlareSink {
    public void logAmberFlare() {
        String data = CWE117_P10_V2_AmberFlare.data;
        Logger amberFlareLogger = Logger.getLogger("amberFlare.audit");
        amberFlareLogger.info("Login attempt for user " + data);
    }
}
