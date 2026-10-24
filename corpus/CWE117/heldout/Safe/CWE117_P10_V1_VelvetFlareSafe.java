import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetFlareSafe {

    public static String data;

    public void handleVelvetFlare() {
        data = System.getenv("VELVET_FLARE_USER");
        (new CWE117_P10_V1_VelvetFlareSafeSink()).logVelvetFlare();
    }
}

class CWE117_P10_V1_VelvetFlareSafeSink {
    public void logVelvetFlare() {
        String data = CWE117_P10_V1_VelvetFlareSafe.data;
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
