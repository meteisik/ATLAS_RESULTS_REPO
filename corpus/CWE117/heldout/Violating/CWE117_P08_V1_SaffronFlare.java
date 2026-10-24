import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronFlare {

    public void handleSaffronFlare() {
        String data;
        data = System.getenv("SAFFRON_FLARE_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronFlareSink()).logSaffronFlare(dataArray);
    }
}

class CWE117_P08_V1_SaffronFlareSink {
    public void logSaffronFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronFlareLogger = Logger.getLogger("saffronFlare.audit");
        saffronFlareLogger.info("Login attempt for user " + data);
    }
}
