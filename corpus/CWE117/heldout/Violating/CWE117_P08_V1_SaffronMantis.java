import java.util.logging.Logger;

public class CWE117_P08_V1_SaffronMantis {

    public void handleSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_SaffronMantisSink()).logSaffronMantis(dataArray);
    }
}

class CWE117_P08_V1_SaffronMantisSink {
    public void logSaffronMantis(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + data);
    }
}
