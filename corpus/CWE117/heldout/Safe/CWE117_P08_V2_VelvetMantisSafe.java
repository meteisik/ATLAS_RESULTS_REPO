import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetMantisSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleVelvetMantis() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_MANTIS_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetMantisSafeSink()).logVelvetMantis(dataArray);
    }
}

class CWE117_P08_V2_VelvetMantisSafeSink {
    public void logVelvetMantis(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
