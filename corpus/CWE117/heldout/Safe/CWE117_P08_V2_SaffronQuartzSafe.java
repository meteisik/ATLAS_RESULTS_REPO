import java.util.logging.Logger;

public class CWE117_P08_V2_SaffronQuartzSafe {

    public void handleSaffronQuartz() {
        String data;
        if (5 == 5) {
            data = System.getenv("SAFFRON_QUARTZ_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SaffronQuartzSafeSink()).logSaffronQuartz(dataArray);
    }
}

class CWE117_P08_V2_SaffronQuartzSafeSink {
    public void logSaffronQuartz(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
