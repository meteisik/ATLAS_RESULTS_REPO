import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronAurora {

    public void handleSaffronAurora() {
        String data;
        data = System.getenv("SAFFRON_AURORA_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronAuroraSink()).logSaffronAurora(dataArray);
    }
}

class CWE117_P08_V1_SaffronAuroraSink {
    public void logSaffronAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + data);
    }
}
