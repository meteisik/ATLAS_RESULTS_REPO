import java.util.logging.Logger;

public class CWE117_P08_V2_SolarFlare {

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
        (new CWE117_P08_V2_SolarFlareSink()).logSolarFlare(dataArray);
    }
}

class CWE117_P08_V2_SolarFlareSink {
    public void logSolarFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger solarFlareLogger = Logger.getLogger("solarFlare.audit");
        solarFlareLogger.info("Login attempt for user " + data);
    }
}
