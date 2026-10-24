import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrQuartz {

    public void runZephyrQuartz() throws SQLException {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_FILTER");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrQuartzSink()).queryZephyrQuartz(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrQuartzSink {
    public void queryZephyrQuartz(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        Statement zephyrQuartzStatement = null;
        ResultSet zephyrQuartzRows = null;
        try {
            zephyrQuartzStatement = zephyrQuartzConnection.createStatement();
            zephyrQuartzRows = zephyrQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrQuartzRows.getRow());
        } finally {
            if (zephyrQuartzRows != null) {
                zephyrQuartzRows.close();
            }
            if (zephyrQuartzStatement != null) {
                zephyrQuartzStatement.close();
            }
            zephyrQuartzConnection.close();
        }
    }
}
