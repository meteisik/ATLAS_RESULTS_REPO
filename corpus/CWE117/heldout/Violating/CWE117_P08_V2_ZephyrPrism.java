import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrPrism {
    private static int privateFive = 5;

    public void handleZephyrPrism() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ZEPHYR_PRISM_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrPrismSink()).logZephyrPrism(dataArray);
    }
}

class CWE117_P08_V2_ZephyrPrismSink {
    public void logZephyrPrism(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + data);
    }
}
