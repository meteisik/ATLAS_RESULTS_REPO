import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V1_SolarCipherSafe {

    public void runSolarCipher() throws SQLException {
        String data;
        data = "foo";
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V1_SolarCipherSafeSink()).querySolarCipher(dataHashMap);
    }
}

class CWE89_P11_V1_SolarCipherSafeSink {
    public void querySolarCipher(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection solarCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:solarCipher");
        Statement solarCipherStatement = null;
        ResultSet solarCipherRows = null;
        try {
            solarCipherStatement = solarCipherConnection.createStatement();
            solarCipherRows = solarCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(solarCipherRows.getRow());
        } finally {
            if (solarCipherRows != null) {
                solarCipherRows.close();
            }
            if (solarCipherStatement != null) {
                solarCipherStatement.close();
            }
            solarCipherConnection.close();
        }
    }
}
