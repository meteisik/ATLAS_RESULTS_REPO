import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronMantisSafe {

    public void handleSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronMantisSafeSink()).logSaffronMantis(dataArray);
    }
}

class CWE117_P08_V1_SaffronMantisSafeSink {
    public void logSaffronMantis(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
