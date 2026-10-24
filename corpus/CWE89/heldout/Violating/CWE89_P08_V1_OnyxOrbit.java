import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxOrbit {

    public void runOnyxOrbit() throws SQLException {
        String data;
        data = System.getenv("ONYX_ORBIT_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxOrbitSink()).queryOnyxOrbit(dataArray);
    }
}

class CWE89_P08_V1_OnyxOrbitSink {
    public void queryOnyxOrbit(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        Statement onyxOrbitStatement = null;
        ResultSet onyxOrbitRows = null;
        try {
            onyxOrbitStatement = onyxOrbitConnection.createStatement();
            onyxOrbitRows = onyxOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxOrbitRows.getRow());
        } finally {
            if (onyxOrbitRows != null) {
                onyxOrbitRows.close();
            }
            if (onyxOrbitStatement != null) {
                onyxOrbitStatement.close();
            }
            onyxOrbitConnection.close();
        }
    }
}
