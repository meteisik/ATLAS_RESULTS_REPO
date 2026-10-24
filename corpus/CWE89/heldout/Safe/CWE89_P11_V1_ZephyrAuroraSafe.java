import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrAuroraSafe {

    public void runZephyrAurora() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrAuroraSafeSink()).queryZephyrAurora(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrAuroraSafeSink {
    public void queryZephyrAurora(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrAurora");
        Statement zephyrAuroraStatement = null;
        ResultSet zephyrAuroraRows = null;
        try {
            zephyrAuroraStatement = zephyrAuroraConnection.createStatement();
            zephyrAuroraRows = zephyrAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrAuroraRows.getRow());
        } finally {
            if (zephyrAuroraRows != null) {
                zephyrAuroraRows.close();
            }
            if (zephyrAuroraStatement != null) {
                zephyrAuroraStatement.close();
            }
            zephyrAuroraConnection.close();
        }
    }
}
