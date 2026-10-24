import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetPrismSafe {
    private static int privateFive = 5;

    public void handleVelvetPrism() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_PRISM_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetPrismSafeSink()).logVelvetPrism(dataArray);
    }
}

class CWE117_P08_V2_VelvetPrismSafeSink {
    public void logVelvetPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetPrismLogger = Logger.getLogger("velvetPrism.audit");
        velvetPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
