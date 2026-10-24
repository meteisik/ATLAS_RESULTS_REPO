import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetFlare {

    public static String data;

    public void handleVelvetFlare() {
        data = System.getenv("VELVET_FLARE_USER");
        (new CWE117_P10_V1_VelvetFlareSink()).logVelvetFlare();
    }
}

class CWE117_P10_V1_VelvetFlareSink {
    public void logVelvetFlare() {
        String data = CWE117_P10_V1_VelvetFlare.data;
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}
