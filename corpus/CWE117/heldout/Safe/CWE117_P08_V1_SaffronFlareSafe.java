import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronFlareSafe {

    public void handleSaffronFlare() {
        String data;
        data = System.getenv("SAFFRON_FLARE_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronFlareSafeSink()).logSaffronFlare(dataArray);
    }
}

class CWE117_P08_V1_SaffronFlareSafeSink {
    public void logSaffronFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
