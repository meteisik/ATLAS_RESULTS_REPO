import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetQuartz {

    public static String data;

    public void handleVelvetQuartz() {
        data = System.getenv("VELVET_QUARTZ_USER");
        (new CWE117_P10_V1_VelvetQuartzSink()).logVelvetQuartz();
    }
}

class CWE117_P10_V1_VelvetQuartzSink {
    public void logVelvetQuartz() {
        String data = CWE117_P10_V1_VelvetQuartz.data;
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + data);
    }
}
