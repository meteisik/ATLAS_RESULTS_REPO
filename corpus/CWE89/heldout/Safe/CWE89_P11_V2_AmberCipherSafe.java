import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runAmberCipher() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberCipherSafeSink()).queryAmberCipher(dataHashMap);
    }
}

class CWE89_P11_V2_AmberCipherSafeSink {
    public void queryAmberCipher(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCipher");
        Statement amberCipherStatement = null;
        ResultSet amberCipherRows = null;
        try {
            amberCipherStatement = amberCipherConnection.createStatement();
            amberCipherRows = amberCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberCipherRows.getRow());
        } finally {
            if (amberCipherRows != null) {
                amberCipherRows.close();
            }
            if (amberCipherStatement != null) {
                amberCipherStatement.close();
            }
            amberCipherConnection.close();
        }
    }
}
