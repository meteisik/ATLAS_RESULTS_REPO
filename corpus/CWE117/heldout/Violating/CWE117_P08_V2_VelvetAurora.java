import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetAurora {

    public void handleVelvetAurora() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("VELVET_AURORA_USER");
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetAuroraSink()).logVelvetAurora(dataArray);
    }
}

class CWE117_P08_V2_VelvetAuroraSink {
    public void logVelvetAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}
