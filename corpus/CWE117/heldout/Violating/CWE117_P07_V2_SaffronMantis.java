import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronMantis {

    public void handleSaffronMantis() {
        String data;
        switch (7) {
        case 7:
            data = (new CWE117_P07_V2_SaffronMantisSource()).readSaffronMantis();
            break;
        default:
            data = null;
            break;
        }
        Logger saffronMantisLogger = Logger.getLogger("saffronMantis.audit");
        saffronMantisLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SaffronMantisSource {
    public String readSaffronMantis() {
        String data;
        data = System.getenv("SAFFRON_MANTIS_USER");
        return data;
    }
}
