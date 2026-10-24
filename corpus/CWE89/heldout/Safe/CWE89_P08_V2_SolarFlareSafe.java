import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_SolarFlareSafe {

    public void runSolarFlare() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_SolarFlareSafeSink()).querySolarFlare(dataArray);
    }
}

class CWE89_P08_V2_SolarFlareSafeSink {
    public void querySolarFlare(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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
