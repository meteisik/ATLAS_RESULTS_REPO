import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetQuartz {
    private static boolean privateReturnsTrue() { return true; }

    public void handleVelvetQuartz() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_QUARTZ_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetQuartzSink()).logVelvetQuartz(dataArray);
    }
}

class CWE117_P08_V2_VelvetQuartzSink {
    public void logVelvetQuartz(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + data);
    }
}
