import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrMantis {

    public void runZephyrMantis() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_MANTIS_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrMantisSink()).queryZephyrMantis(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrMantisSink {
    public void queryZephyrMantis(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrMantis");
        Statement zephyrMantisStatement = null;
        ResultSet zephyrMantisRows = null;
        try {
            zephyrMantisStatement = zephyrMantisConnection.createStatement();
            zephyrMantisRows = zephyrMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrMantisRows.getRow());
        } finally {
            if (zephyrMantisRows != null) {
                zephyrMantisRows.close();
            }
            if (zephyrMantisStatement != null) {
                zephyrMantisStatement.close();
            }
            zephyrMantisConnection.close();
        }
    }
}
