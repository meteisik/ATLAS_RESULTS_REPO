import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;

public class CWE89_P11_V2_AmberMantis {
    private static int privateFive = 5;

    public void runAmberMantis() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("AMBER_MANTIS_FILTER");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE89_P11_V2_AmberMantisSink()).queryAmberMantis(dataHashMap);
    }
}

class CWE89_P11_V2_AmberMantisSink {
    public void queryAmberMantis(HashMap<Integer, String> dataHashMap) throws SQLException {
        String data = dataHashMap.get(2);
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        Statement amberMantisStatement = null;
        ResultSet amberMantisRows = null;
        try {
            amberMantisStatement = amberMantisConnection.createStatement();
            amberMantisRows = amberMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberMantisRows.getRow());
        } finally {
            if (amberMantisRows != null) {
                amberMantisRows.close();
            }
            if (amberMantisStatement != null) {
                amberMantisStatement.close();
            }
            amberMantisConnection.close();
        }
    }
}
