import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetPrism {
    private static boolean privateTrue = true;

    public void handleVelvetPrism() {
        String data;
        if (privateTrue) {
            data = (new CWE117_P07_V2_VelvetPrismSource()).readVelvetPrism();
        } else {
            data = null;
        }
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetPrismSource {
    public String readVelvetPrism() {
        String data;
        data = System.getenv("VELVET_PRISM_USER");
        return data;
    }
}
