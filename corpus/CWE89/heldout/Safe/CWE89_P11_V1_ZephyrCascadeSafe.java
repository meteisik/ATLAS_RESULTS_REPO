import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrCascadeSafe {

    public void runZephyrCascade() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrCascadeSafeSink()).queryZephyrCascade(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrCascadeSafeSink {
    public void queryZephyrCascade(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCascade");
        Statement zephyrCascadeStatement = null;
        ResultSet zephyrCascadeRows = null;
        try {
            zephyrCascadeStatement = zephyrCascadeConnection.createStatement();
            zephyrCascadeRows = zephyrCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCascadeRows.getRow());
        } finally {
            if (zephyrCascadeRows != null) {
                zephyrCascadeRows.close();
            }
            if (zephyrCascadeStatement != null) {
                zephyrCascadeStatement.close();
            }
            zephyrCascadeConnection.close();
        }
    }
}
