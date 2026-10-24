import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberAurora {

    public void runAmberAurora() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("AMBER_AURORA_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberAuroraSink()).queryAmberAurora(dataHashMap);
    }
}

class CWE89_P11_V2_AmberAuroraSink {
    public void queryAmberAurora(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        Statement amberAuroraStatement = null;
        ResultSet amberAuroraRows = null;
        try {
            amberAuroraStatement = amberAuroraConnection.createStatement();
            amberAuroraRows = amberAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberAuroraRows.getRow());
        } finally {
            if (amberAuroraRows != null) {
                amberAuroraRows.close();
            }
            if (amberAuroraStatement != null) {
                amberAuroraStatement.close();
            }
            amberAuroraConnection.close();
        }
    }
}
