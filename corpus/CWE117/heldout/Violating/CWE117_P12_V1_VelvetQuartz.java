import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetQuartz {

    public void handleVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_USER");
        CWE117_P12_V1_VelvetQuartzBase baseObject = new CWE117_P12_V1_VelvetQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetQuartzBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetQuartzSink extends CWE117_P12_V1_VelvetQuartzBase {
    public void action(String data) {
        Logger velvetQuartzLogger = Logger.getLogger("velvetQuartz.audit");
        velvetQuartzLogger.info("Login attempt for user " + data);
    }
}
