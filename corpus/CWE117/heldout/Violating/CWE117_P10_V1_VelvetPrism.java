import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetPrism {

    public static String data;

    public void handleVelvetPrism() {
        data = System.getenv("VELVET_PRISM_USER");
        (new CWE117_P10_V1_VelvetPrismSink()).logVelvetPrism();
    }
}

class CWE117_P10_V1_VelvetPrismSink {
    public void logVelvetPrism() {
        String data = CWE117_P10_V1_VelvetPrism.data;
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + data);
    }
}
