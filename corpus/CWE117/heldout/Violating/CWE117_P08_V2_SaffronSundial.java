import java.util.logging.Logger;

public class CWE117_P08_V2_SaffronSundial {
    private static boolean privateTrue = true;

    public void handleSaffronSundial() {
        String data;
        if (privateTrue) {
            data = System.getenv("SAFFRON_SUNDIAL_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SaffronSundialSink()).logSaffronSundial(dataArray);
    }
}

class CWE117_P08_V2_SaffronSundialSink {
    public void logSaffronSundial(String[] dataArray) {
        String data = dataArray[2];
        Logger saffronSundialLogger = Logger.getLogger("saffronSundial.audit");
        saffronSundialLogger.info("Login attempt for user " + data);
    }
}
