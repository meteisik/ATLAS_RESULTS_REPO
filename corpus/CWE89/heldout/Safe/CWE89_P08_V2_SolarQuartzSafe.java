import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_SolarQuartzSafe {

    public void runSolarQuartz() throws SQLException {
        String data;
        while (true) {
            data = "foo";
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_SolarQuartzSafeSink()).querySolarQuartz(dataArray);
    }
}

class CWE89_P08_V2_SolarQuartzSafeSink {
    public void querySolarQuartz(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection solarQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarQuartz");
        Statement solarQuartzStatement = null;
        ResultSet solarQuartzRows = null;
        try {
            solarQuartzStatement = solarQuartzConnection.createStatement();
            solarQuartzRows = solarQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarQuartzRows.getRow());
        } finally {
            if (solarQuartzRows != null) {
                solarQuartzRows.close();
            }
            if (solarQuartzStatement != null) {
                solarQuartzStatement.close();
            }
            solarQuartzConnection.close();
        }
    }
}
