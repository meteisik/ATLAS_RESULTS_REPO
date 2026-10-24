import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetFlareSafe {

    public void handleVelvetFlare() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_VelvetFlareSafeSource()).readVelvetFlare();
        } else {
            data = null;
        }
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetFlareSafeSource {
    public String readVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_USER");
        return data;
    }
}
