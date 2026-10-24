import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetSignal {

    public static String data;

    public void handleVelvetSignal() {
        data = System.getenv("VELVET_SIGNAL_USER");
        (new CWE117_P10_V1_VelvetSignalSink()).logVelvetSignal();
    }
}

class CWE117_P10_V1_VelvetSignalSink {
    public void logVelvetSignal() {
        String data = CWE117_P10_V1_VelvetSignal.data;
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + data);
    }
}
