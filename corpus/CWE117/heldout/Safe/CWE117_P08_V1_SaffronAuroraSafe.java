import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronAuroraSafe {

    public void handleSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronAuroraSafeSink()).logSaffronAurora(dataArray);
    }
}

class CWE117_P08_V1_SaffronAuroraSafeSink {
    public void logSaffronAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
