import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_OnyxOrbit {

    static class Container {
        public String containerOne;
    }

    public void runOnyxOrbit() throws SQLException {
        String data;
        data = System.getenv("ONYX_ORBIT_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_OnyxOrbitSink()).queryOnyxOrbit(dataContainer);
    }
}

class CWE89_P09_V1_OnyxOrbitSink {
    public void queryOnyxOrbit(CWE89_P09_V1_OnyxOrbit.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
