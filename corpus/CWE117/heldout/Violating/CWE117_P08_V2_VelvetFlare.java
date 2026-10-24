import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetFlare {
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
        (new CWE117_P08_V2_VelvetFlareSink()).logVelvetFlare(dataArray);
    }
}

class CWE117_P08_V2_VelvetFlareSink {
    public void logVelvetFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}
