import java.util.logging.Logger;

public class CWE117_P12_V1_VelvetSignal {

    public void handleVelvetSignal() {
        String data;
        data = System.getenv("VELVET_SIGNAL_USER");
        CWE117_P12_V1_VelvetSignalBase baseObject = new CWE117_P12_V1_VelvetSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VelvetSignalBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VelvetSignalSink extends CWE117_P12_V1_VelvetSignalBase {
    public void action(String data) {
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + data);
    }
}
