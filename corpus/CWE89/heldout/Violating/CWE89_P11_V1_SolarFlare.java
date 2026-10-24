import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SolarFlare {

    public void runSolarFlare() throws SQLException {
        String data;
        data = System.getenv("SOLAR_FLARE_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SolarFlareSink()).querySolarFlare(dataHashMap);
    }
}

class CWE89_P11_V1_SolarFlareSink {
    public void querySolarFlare(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection solarFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarFlare");
        Statement solarFlareStatement = null;
        ResultSet solarFlareRows = null;
        try {
            solarFlareStatement = solarFlareConnection.createStatement();
            solarFlareRows = solarFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarFlareRows.getRow());
        } finally {
            if (solarFlareRows != null) {
                solarFlareRows.close();
            }
            if (solarFlareStatement != null) {
                solarFlareStatement.close();
            }
            solarFlareConnection.close();
        }
    }
}
