import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_ZephyrCipherSafe {

    public void runZephyrCipher() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_ZephyrCipherSafeSink()).queryZephyrCipher(dataHashMap);
    }
}

class CWE89_P11_V1_ZephyrCipherSafeSink {
    public void queryZephyrCipher(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection zephyrCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrCipher");
        Statement zephyrCipherStatement = null;
        ResultSet zephyrCipherRows = null;
        try {
            zephyrCipherStatement = zephyrCipherConnection.createStatement();
            zephyrCipherRows = zephyrCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrCipherRows.getRow());
        } finally {
            if (zephyrCipherRows != null) {
                zephyrCipherRows.close();
            }
            if (zephyrCipherStatement != null) {
                zephyrCipherStatement.close();
            }
            zephyrCipherConnection.close();
        }
    }
}
