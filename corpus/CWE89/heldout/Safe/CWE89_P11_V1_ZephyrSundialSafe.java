import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrSundialSafe {

    public void runZephyrSundial() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrSundialSafeSink()).queryZephyrSundial(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrSundialSafeSink {
    public void queryZephyrSundial(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrSundial");
        Statement zephyrSundialStatement = null;
        ResultSet zephyrSundialRows = null;
        try {
            zephyrSundialStatement = zephyrSundialConnection.createStatement();
            zephyrSundialRows = zephyrSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrSundialRows.getRow());
        } finally {
            if (zephyrSundialRows != null) {
                zephyrSundialRows.close();
            }
            if (zephyrSundialStatement != null) {
                zephyrSundialStatement.close();
            }
            zephyrSundialConnection.close();
        }
    }
}
