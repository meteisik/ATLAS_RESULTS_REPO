import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetAuroraSafe {

    public void handleVelvetAurora() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VELVET_AURORA_USER");
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetAuroraSafeSink()).logVelvetAurora(dataArray);
    }
}

class CWE117_P08_V2_VelvetAuroraSafeSink {
    public void logVelvetAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
