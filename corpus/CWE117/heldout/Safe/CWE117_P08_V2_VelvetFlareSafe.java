import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetFlareSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleVelvetFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_FLARE_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetFlareSafeSink()).logVelvetFlare(dataArray);
    }
}

class CWE117_P08_V2_VelvetFlareSafeSink {
    public void logVelvetFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
