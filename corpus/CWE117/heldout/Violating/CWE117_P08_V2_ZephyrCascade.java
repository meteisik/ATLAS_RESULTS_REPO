import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrCascade {

    public void handleZephyrCascade() {
        String data;
        if (true) {
            data = System.getenv("ZEPHYR_CASCADE_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrCascadeSink()).logZephyrCascade(dataArray);
    }
}

class CWE117_P08_V2_ZephyrCascadeSink {
    public void logZephyrCascade(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + data);
    }
}
