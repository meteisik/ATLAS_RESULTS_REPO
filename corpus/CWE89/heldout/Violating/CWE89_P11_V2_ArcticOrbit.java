import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_ArcticOrbit {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runArcticOrbit() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_ORBIT_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_ArcticOrbitSink()).queryArcticOrbit(dataHashMap);
    }
}

class CWE89_P11_V2_ArcticOrbitSink {
    public void queryArcticOrbit(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
        Statement arcticOrbitStatement = null;
        ResultSet arcticOrbitRows = null;
        try {
            arcticOrbitStatement = arcticOrbitConnection.createStatement();
            arcticOrbitRows = arcticOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticOrbitRows.getRow());
        } finally {
            if (arcticOrbitRows != null) {
                arcticOrbitRows.close();
            }
            if (arcticOrbitStatement != null) {
                arcticOrbitStatement.close();
            }
            arcticOrbitConnection.close();
        }
    }
}
