import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SilentOrbit {

    public void runSilentOrbit() throws SQLException {
        String data;
        data = System.getenv("SILENT_ORBIT_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SilentOrbitSink()).querySilentOrbit(dataHashMap);
    }
}

class CWE89_P11_V1_SilentOrbitSink {
    public void querySilentOrbit(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        Statement silentOrbitStatement = null;
        ResultSet silentOrbitRows = null;
        try {
            silentOrbitStatement = silentOrbitConnection.createStatement();
            silentOrbitRows = silentOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(silentOrbitRows.getRow());
        } finally {
            if (silentOrbitRows != null) {
                silentOrbitRows.close();
            }
            if (silentOrbitStatement != null) {
                silentOrbitStatement.close();
            }
            silentOrbitConnection.close();
        }
    }
}
