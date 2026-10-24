import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrSignalSafe {

    public void runZephyrSignal() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrSignalSafeSink()).queryZephyrSignal(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrSignalSafeSink {
    public void queryZephyrSignal(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSignal");
        Statement zephyrSignalStatement = null;
        ResultSet zephyrSignalRows = null;
        try {
            zephyrSignalStatement = zephyrSignalConnection.createStatement();
            zephyrSignalRows = zephyrSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrSignalRows.getRow());
        } finally {
            if (zephyrSignalRows != null) {
                zephyrSignalRows.close();
            }
            if (zephyrSignalStatement != null) {
                zephyrSignalStatement.close();
            }
            zephyrSignalConnection.close();
        }
    }
}
