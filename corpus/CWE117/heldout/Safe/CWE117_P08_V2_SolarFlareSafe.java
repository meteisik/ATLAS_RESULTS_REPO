import java.util.logging.Logger;

public class CWE117_P08_V2_SolarFlareSafe {

    public void handleSolarFlare() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SOLAR_FLARE_USER");
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SolarFlareSafeSink()).logSolarFlare(dataArray);
    }
}

class CWE117_P08_V2_SolarFlareSafeSink {
    public void logSolarFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
