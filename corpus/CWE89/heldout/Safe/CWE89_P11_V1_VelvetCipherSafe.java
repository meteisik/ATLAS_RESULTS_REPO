import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_VelvetCipherSafe {

    public void runVelvetCipher() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_VelvetCipherSafeSink()).queryVelvetCipher(dataHashMap);
    }
}

class CWE89_P11_V1_VelvetCipherSafeSink {
    public void queryVelvetCipher(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        Statement velvetCipherStatement = null;
        ResultSet velvetCipherRows = null;
        try {
            velvetCipherStatement = velvetCipherConnection.createStatement();
            velvetCipherRows = velvetCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetCipherRows.getRow());
        } finally {
            if (velvetCipherRows != null) {
                velvetCipherRows.close();
            }
            if (velvetCipherStatement != null) {
                velvetCipherStatement.close();
            }
            velvetCipherConnection.close();
        }
    }
}
