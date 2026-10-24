import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SolarQuartz {

    public void runSolarQuartz() throws SQLException {
        String data;
        data = System.getenv("SOLAR_QUARTZ_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SolarQuartzSink()).querySolarQuartz(dataHashMap);
    }
}

class CWE89_P11_V1_SolarQuartzSink {
    public void querySolarQuartz(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
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
